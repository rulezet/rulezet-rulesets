rule Trojan_Autorun_Dropped_Generic_Dacic_06B5CF0E_A_3A6AA980_70_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_70_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f1e3447d940993b3f95f439f6c839af0a9da59bd7f51221aa6b3f519f1f60b8"

  strings:
    $s1  = "lectionner l'environnement le plus compatible. -->" fullword ascii
    $s2  = "tes de dialogue communes de Windows (Windows XP et version ult" fullword ascii
    $s3  = "Vista -->" fullword ascii
    $s4  = " - Change all my Photos into Icons" fullword wide
    $s5  = "Operation successful" fullword wide
    $s6  = "Operation cancelled by the user" fullword wide
    $s7  = "Change to 96 * 96" fullword wide
    $s8  = "Change to 48 * 48" fullword wide
    $s9  = "Change to 32 * 32" fullword wide
    $s10 = "mes pour les contr" fullword ascii
    $s11 = " Convert Icon" fullword wide
    $s12 = " transformer en ic" fullword wide
    $s13 = " Convert to Icon 1.1.1 " fullword wide
    $s14 = "Convert your Photos to Icons" fullword ascii
    $s15 = "4.6 et qui optent pour ce param" fullword ascii
    $s16 = "  <!-- Indique que l'application prend en charge DPI et qu'elle n'est pas automatiquement mise " fullword ascii
    $s17 = "galement affecter la valeur 'true' au param" fullword ascii
    $s18 = "Convert to Icon 1.1.1" fullword ascii
    $s19 = "Select my Photo to convert" fullword wide
    $s20 = "Open my Photo" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}