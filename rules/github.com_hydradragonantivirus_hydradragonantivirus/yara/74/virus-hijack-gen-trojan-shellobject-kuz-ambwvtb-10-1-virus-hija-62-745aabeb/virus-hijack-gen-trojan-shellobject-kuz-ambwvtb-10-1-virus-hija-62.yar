rule _Virus_Hijack_Gen_Trojan_ShellObject_KuZ_amBwvTb_10_1_Virus_Hija_62 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.KuZ@amBwvTb_10_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.KuZ@amBwvTb_11_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.KuZ@amBwvTb_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c56ebda9d69cd076d17f7a71418d14c7a0863925f009205bf634a56a305410e8"
    hash2       = "eb1e0705ac53c4197a8b463c908c806a52a6f25ff64dc679ab6a122df2b2d329"
    hash3       = "01926e279514e9f218b61ecb2645f63b0a5790384dba2b188f42d7373c6ebcf4"

  strings:
    $s1  = " 2013 Enter Feeldivide may Corporation. All rights reserved" fullword wide
    $s2  = "When gl" fullword ascii
    $s3  = "            <Stage package=\"Package_482_for_KB3125574~31bf3856ad364e35~x86~~6.1.4.4\" update=\"312557" fullword wide
    $s4  = "            <Install package=\"Package_404_for_KB3125574~31bf3856ad364e35~x86~~6.1.4.4\" update=\"3125574-2033_neutral_LDR\"/>" fullword wide
    $s5  = "Study Evenshine" fullword wide
    $s6  = "Enter Feeldivide may" fullword wide
    $s7  = "Enter Feeldivide may Eatdream Butwant" fullword wide
    $s8  = "            <Resolve package=\"Microsoft-Windows-Common-Drivers-Package~31bf3856ad364e35~x86~en-US~6.1.7600.16385\" update=\"INF" wide
    $s9  = "            <Resolve package=\"Microsoft-Windows-Common-Drivers-Package~31bf3856ad364e35~x86~en-US~6.1.7600.16385\" update=\"ixe" wide
    $s10 = "            <Resolve package=\"Microsoft-Windows-Common-Drivers-Package~31bf3856ad364e35~x86~en-US~6.1.7600.16385\" update=\"INF" wide
    $s11 = "            <Resolve package=\"Microsoft-Windows-Common-Drivers-Package~31bf3856ad364e35~x86~en-US~6.1.7600.16385\" update=\"INF" wide
    $s12 = "            <Resolve package=\"Microsoft-Windows-Common-Drivers-Package~31bf3856ad364e35~x86~en-US~6.1.7600.16385\" update=\"INF" wide
    $s13 = "            <Resolve package=\"Microsoft-Windows-Common-Drivers-Package~31bf3856ad36" fullword wide
    $s14 = "            <Resolve package=\"Microsoft-Windows-Common-Modem-Drivers-Package~31bf3856ad364e35~x86~en-US~6.1.7600.16385\" update" wide
    $s15 = "            <Resolve package=\"Microsoft-Windows-Common-Modem-Drivers-Package~31bf3856ad364e35~x86~en-US~6.1.7600.16385\" update" wide
    $s16 = "            <Resolve package=\"Microsoft-Windows-Common-Modem-Drivers-Package~31bf3856ad364e35~x86~en-US~6.1.7600.16385\" update" wide
    $s17 = "            <Resolve package=\"Microsoft-Windows-Common-Modem-Drivers-Package~31bf3856ad364e35~x86~en-US~6.1.7600.16385\" update" wide
    $s18 = "            <Resolve package=\"Microsoft-Windows-Common-Modem-Drivers-Package~31bf3856ad364e35~x86~en-US~6.1.7600.16385\" update" wide
    $s19 = "            <Resolve package=\"Microsoft-Windows-Common-Modem-Drivers-Package~31bf3856ad364e35~x86~en-US~6.1.7600.16385\" update" wide
    $s20 = "            <Resolve package=\"Microsoft-Windows-Common-Modem-Drivers-Package~31bf3856ad364e35~x86~en-US~6.1.7600.16385\" update" wide

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}