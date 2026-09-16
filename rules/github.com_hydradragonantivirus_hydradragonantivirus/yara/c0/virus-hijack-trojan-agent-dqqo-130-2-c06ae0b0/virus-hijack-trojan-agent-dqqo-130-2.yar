rule Virus_Hijack_Trojan_Agent_DQQO_130_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_130_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f07a12575587d63590c4ad4b5c8fd3b203bf3d8977bbabbb184683b9b004dacd"

  strings:
    $s1  = "Elevate to Admin Privileges failed!" fullword ascii
    $s2  = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.5-c014 79.151481, 2013/03/" ascii
    $s3  = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.5-c014 79.151481, 2013/03/" ascii
    $s4  = "open process err errcode: %d, processid:%d" fullword ascii
    $s5  = "copy wechat.exe. renameFile faild. path=%s, lastErr=%d" fullword ascii
    $s6  = "quit and start wechat.exe" fullword ascii
    $s7  = "Elevate to Admin Privileges" fullword ascii
    $s8  = "get the pack version: m_patchVersion: %d, version: %s" fullword ascii
    $s9  = "exit current instance for the elevation." fullword ascii
    $s10 = "already have admin privileges" fullword ascii
    $s11 = "Run NowAUpdate error. Download and install latest version at our website.hUpdate error. Download and install the latest version " wide
    $s12 = "setDisplayVersionReg. write reg faild.ret=%d, lastErr=%d" fullword ascii
    $s13 = ":documentID=\"xmp.did:3ECFFD20565111E3B6B283CE8493160B\"/> </rdf:Description> </rdf:RDF> </x:xmpmeta> <?xpacket end=\"r\"?>" fullword ascii
    $s14 = ":documentID=\"xmp.did:3ECFFD24565111E3B6B283CE8493160B\"/> </rdf:Description> </rdf:RDF> </x:xmpmeta> <?xpacket end=\"r\"?>Tt4=" fullword ascii
    $s15 = "get new file info failed com %s" fullword ascii
    $s16 = "cancelled elevation" fullword ascii
    $s17 = "rename wechat.exe error." fullword ascii
    $s18 = "copy wechat.exe error." fullword ascii
    $s19 = "get new file info failed" fullword ascii
    $s20 = "readRegAndConfig[%s], regtype:%d is different from initype:%d" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}