import "pe"
rule _Virus_Autorun_Dropped_Win32_Worm_VB_NXJ_Virus_Autorun_Dropped_W_206 {
  meta:
    description = "datamaliciousorder - from files Virus.Autorun_Dropped.Win32.Worm.VB.NXJ.vir, Virus.Autorun_Dropped.Win32.Worm.VB.NXJ_1.vir, Virus.Hijack_Dropped.Win32.Worm.VB.NXJ_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.u8Z@aqOJzSd_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0b79a57a926f801baca06e13180644ff8a9531494ec2bc0fb219ba35b9e51f5"
    hash2       = "0b5dc186b2c779853a25d3f0d3bc3470a319fb2d976594e000f7f06c23b18e03"
    hash3       = "6eab816a4bcf7258e1b7ee52a7113aaa36abd6ad3ae7508c094aacf6cff19020"
    hash4       = "d6767a4b06185a363a0348866269fb91d958be7963fa9f901ec3f2503d418fef"

  strings:
    $s1  = "normally running please run \"srRepair.exe\" to Repair or " fullword ascii
    $s2  = "spRepair.exe para reparar!  " fullword ascii
    $s3  = "effectuer ? spRepair.exe ? pour r" fullword ascii
    $s4  = "virus software te sluiten en \"spRepair.exe\" uit te " fullword ascii
    $s5  = "rus e para realizar spRepair.exe " fullword ascii
    $s6  = "We recommend you only run MicrosoftFirewall (TM) instead " fullword ascii
    $s7  = "Firewall beta version." fullword ascii
    $s8  = "dem Ausgabe Windows System." fullword ascii
    $s9  = "n podemos 5.x compatible (el " fullword ascii
    $s10 = "l'autre disposition compteur-virale d'obtenir une " fullword ascii
    $s11 = "dition pouvons 5.x compatible (le syst" fullword ascii
    $s12 = "erreichen k?nnen kompatibles 5.x (das XP System) " fullword ascii
    $s13 = "[Multi-country languages Version]" fullword ascii
    $s14 = "compatible with Windows OS 5.x(WinXP or higher)" fullword ascii
    $s15 = "movimento (TM) para substituir a outra disposi??o " fullword ascii
    $s16 = "parer !  " fullword ascii
    $s17 = "feu de Microsoft de mouvement (TM) pour remplacer " fullword ascii
    $s18 = "Deze disk ontvangt de firewall van Microsoft de " fullword ascii
    $s19 = "Uninstall other antivirus solutions." fullword ascii
    $s20 = "movimiento (TM) para substituir la otra disposici" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "27fb6bc8c88cb43fbf3b133e72a42962" and (8 of them)
    ) or (all of them)
}