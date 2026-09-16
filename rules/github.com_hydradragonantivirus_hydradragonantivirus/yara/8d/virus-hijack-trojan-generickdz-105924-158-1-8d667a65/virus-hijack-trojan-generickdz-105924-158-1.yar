rule Virus_Hijack_Trojan_GenericKDZ_105924_158_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_158_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4a665cbc6dadf0f8cc7ecaca619703282d2947c8582c682f33113c863900281c"

  strings:
    $s1 = "User-Agent:Mozilla/5.0+(compatible;+Baiduspider/2.0;++http://www.baidu.com/search/spider.html)" fullword ascii
    $s2 = "User-Agent:Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; SV1)" fullword ascii
    $s3 = "Windows server 2008" fullword ascii
    $s4 = "Windows server 2003" fullword ascii
    $s5 = "Windows server 2000" fullword ascii
    $s6 = "Error! %d" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}