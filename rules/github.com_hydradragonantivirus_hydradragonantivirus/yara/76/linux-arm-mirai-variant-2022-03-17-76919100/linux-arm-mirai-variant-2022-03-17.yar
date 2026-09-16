rule Linux_ARM_Mirai_Variant_2022_03_17 {
  meta:
    description = "Detects new ARM Mirai variant"
    author      = "Mehmet Ali Kerimoglu a.k.a. CYB3RMX"
    date        = "2022-03-17"
    hash1       = "076e87c238d07821243660feb692c96dee92569be3e2867e6b46e7cb5a6593ef"

  strings:
    $useragent1 = "Mozilla/4.0 (Compatible; MSIE 8.0; Windows NT 5.2; Trident/6.0)" wide ascii
    $useragent2 = "Mozilla/4.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/5.0)" wide ascii
    $useragent3 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; pl) Opera 11.00" wide ascii
    $useragent4 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36" wide ascii
    $useragent5 = "Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51" wide ascii
    $useragent6 = "Opera/9.80 (X11; Linux i686; Ubuntu/14.10) Presto/2.12.388 Version/12.16" wide ascii
    $strw1      = /RyMGang/ nocase
    $strw2      = "TSource Engine Query" wide ascii
    $reqq1      = "GET /cdn-cgi/l/chk_captcha HTTP/1.1" wide ascii
    $pa1        = "/proc/net/route" wide ascii
    $pa2        = "/usr/bin/python" wide ascii
    $pa3        = "/usr/sbin/dropbear" wide ascii
    $pa4        = "/etc/hosts" wide ascii
    $pa5        = "/etc/config/hosts" wide ascii
    $pa6        = "/etc/config/resolv.conf" wide ascii
    $pa7        = "/etc/resolv.conf" wide ascii
    $debstr1    = "/home/firmware/build/temp-armv4l/gcc-core/gcc/config/arm/lib1funcs.asm" wide ascii
    $debstr2    = "/home/firmware/build/temp-armv4l/build-gcc/gcc" wide ascii
    $debstr3    = "/home/firmware/build/temp-armv4l/gcc-core/gcc/config/arm" wide ascii
    $fst1       = "ieee754-df.S" wide ascii
    $fst2       = "lib1funcs.asm" wide ascii

  condition:
    uint16(0) == 0x457f and ((4 or all of ($useragent*)) and (all of ($strw*)) and (all of ($reqq1)) and (5 or all of ($pa*)) and (all of ($debstr*)) and (all of ($fst*)))
}