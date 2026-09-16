import "pe"
rule _Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_333_2_Tro_68 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_333_2.vir, Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_334_2.vir, Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_336_2.vir, Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_337_2.vir, Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_338_2.vir, Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_339_2.vir, Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_340_2.vir, Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_341_2.vir, Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_34_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1bb367ff3450a5f0b9c60090cde67f7412b5bc8590622f3f8a6a5d66addaf721"
    hash2       = "17f36f9ac30e7ec160932fb3ef8efcc7ba779a63fe7e2510857a2e6d2909cb32"
    hash3       = "82d2e2a8529d4704d2eabfb845dc262234b73866819ef835e291c7f9818aa9b1"
    hash4       = "4bc4dff91705c7d4494daf2cade0d36f6242bcef6764d8487192fec9469b5299"
    hash5       = "c3662f65c455c8e16f70e3443056b4f924278ba5c68c46bc38f8084ca3fb36a7"
    hash6       = "4b1fa53e1acfb5a328d7af9a76809fe1277bd8d8a8cc43081607fc4929f6198e"
    hash7       = "34c3f1bc4872912b7fcc4ca0c0b4825fcee90df86d9218c8c7d557f852ed3af1"
    hash8       = "6585676245e22cca9f08c5a2f4b7b3020dd02e544a9caa57b1df22687a43192f"
    hash9       = "466a7a4bfd7d7bd3a21da0a70eba84be27533dd1f42b44cb50b559524870b4fb"

  strings:
    $x1  = "{\"active_bit\":false,\"active_permissions\":{\"api\":[\"activeTab\",\"browsingData\",\"contentSettings\",\"contextMenus\",\"coo" ascii
    $s2  = "SELECT host,name,value,expiry FROM moz_cookies where host='.facebook.com';" fullword ascii
    $s3  = "{\"domain\":\".facebook.com\",\"expirationDate\":\"\",\"hostOnly\":false,\"httpOnly\":true,\"name\":\"" fullword ascii
    $s4  = "s_overrides\":{\"search_provider\":{\"encoding\":\"UTF-8\",\"favicon_url\":\"https://www.ctcodeinfo.com/favicon.ico\",\"is_defau" ascii
    $s5  = "{\"domain\":\".amazon.com\",\"expirationDate\":\"\",\"hostOnly\":false,\"httpOnly\":true,\"name\":\"" fullword ascii
    $s6  = "select host_key,name,encrypted_value,expires_utc from cookies where  host_key like '" fullword ascii
    $s7  = "select * from logins where blacklisted_by_user=0  and  origin_url like '%" fullword ascii
    $s8  = "select * from logins where blacklisted_by_user=0" fullword ascii
    $s9  = "{\"domain\":\"%s\",\"expirationDate\":%I64u,\"hostOnly\":false,\"httpOnly\":true,\"name\":\"%s\",\"path\":\"/\",\"secure\":true," ascii
    $s10 = "es\":true,\"js\":[\"js/jquery-3.3.1.min.js\",\"js/content.js\"],\"match_about_blank\":true,\"matches\":[\"http://*/*\",\"https:/" ascii
    $s11 = "{\"domain\":\"%s\",\"expirationDate\":%I64u,\"hostOnly\":false,\"httpOnly\":true,\"name\":\"%s\",\"path\":\"/\",\"secure\":true," ascii
    $s12 = "{\"active_bit\":false,\"active_permissions\":{\"api\":[\"activeTab\",\"browsingData\",\"contentSettings\",\"contextMenus\",\"coo" ascii
    $s13 = "\",\"downloads\",\"privacy\",\"contentSettings\",\"webNavigation\",\"contextMenus\"],\"version\":\"9.86.66\"},\"needs_sync\":tru" ascii
    $s14 = "{\"domain\":\"%s\",\"expirationDate\":\"%I64u\",\"hostOnly\":false,\"httpOnly\":true,\"name\":\"%s\",\"path\":\"/\",\"secure\":t" ascii
    $s15 = "{\"domain\":\"%s\",\"expirationDate\":\"%I64u\",\"hostOnly\":false,\"httpOnly\":true,\"name\":\"%s\",\"path\":\"/\",\"secure\":t" ascii
    $s16 = "\\Google\\Chrome\\User Data\\Profile 1\\Login Data" fullword ascii
    $s17 = "\\Login Data" fullword ascii
    $s18 = "\\Google\\Chrome\\User Data\\Default\\Login Data" fullword ascii
    $s19 = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0; .NET CLR 2.0.50727; SLCC2; .NET CLR 3.5.30729; .NET " ascii
    $s20 = "err : write reg failed(RegCreateKeyExA)" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "d69e4c13e25f0ad622344ac56118c0df" and (1 of ($x*) and 4 of them)
    ) or (all of them)
}