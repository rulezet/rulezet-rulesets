rule _Trojan_Danger_Trojan_GenericKD_46147426_Virus_Hijack_Gen_Trojan_198 {
  meta:
    description = "datamaliciousorder - from files Trojan.Danger_Trojan.GenericKD.46147426.vir, Virus.Hijack_Gen.Trojan.ShellObject.dWW@aOfWMFe_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "51cf85f0909adb4c6b6473126e86916877768b1a1233cca35c189529e226cb43"
    hash2       = "37e1c09c957de9407fb977d32f7e07c08875695abfc4ae017f4ef7c406b001e2"

  strings:
    $s1  = "\\An operating system error occurred during installation. Please download Google Chrome again.\\An operating system error occurr" wide
    $s2  = "Failed to get path to setup.exe." fullword ascii
    $s3  = "Removing store DM token command" fullword ascii
    $s4  = "SThe installer archive is corrupted or invalid. Please download Google Chrome again.WEl archivo de instalaci" fullword wide
    $s5  = ".SThe installer archive is corrupted or invalid. Please download Google Chrome again." fullword wide
    $s6  = "HArsip instalatur rusak atau tidak valid. Download kembali Google Chrome.FUppsetningarsafnskr" fullword wide
    $s7  = "r alle Nutzer auf Ihrem Computer installiert.T" fullword wide
    $s8  = " posterior.3Google Chrome vy" fullword wide
    $s9  = " aplikace\"Apps i udviklerversionen af Chrome" fullword wide
    $s10 = "Google Chrome Dev (mDNS-In),Udviklerversionen af Google Chrome (mDNS-In)" fullword wide
    $s11 = "ivatele.EGoogle Chrome er allerede installeret for alle brugere p" fullword wide
    $s12 = " computeren.IGoogle Chrome ist bereits f" fullword wide
    $s13 = "lador no ha pogut descomprimir el fitxer. Torna a baixar Google Chrome." fullword wide
    $s14 = " archiwum. Pobierz Google Chrome ponownie.YHouve uma falha no instalador ao descompactar o arquivo. Baixe o Google Chrome novame" wide
    $s15 = "sImpossible d'installer la version de Google" fullword wide
    $s16 = "Removed (legacy) stage information; switching to channel: " fullword ascii
    $s17 = " Chrome Beta " fullword wide
    $s18 = "ns de valores controlados de Chrome" fullword wide
    $s19 = "FRegula de intrare pentru Google Chrome pentru a permite traficul mDNS.F" fullword wide
    $s20 = "NGoogle Chrome Dev'in mDNS trafi" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}