import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_i8Z_aGN6KMb_1_2_Virus_Hijac_259 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.i8Z@aGN6KMb_1_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.LuZ@aiy413e_5.vir, Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_14_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.m0Z@aiqugi_9_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.m9Z@aG4fkNb_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1732c9bd06b7b849f34b16f3bcbc8d388a95eaf8bb6f48d8eb26f714aa6f6560"
    hash2       = "f54f2085c2b27063cfe126a418867e95a89d5884bf5436841f74a6e4dfe0beaf"
    hash3       = "9eea96a86ee8edad7ab68197d4bc0e62642697d1feabce5031dae4f1981a0817"
    hash4       = "df3e21c46d92a2e94d1db64b6a635c0653efa4085f7249688e5ce55102119dec"
    hash5       = "c39695c9f4a6e1d205861f95eb4a9430f5fe4436b6b55d4ca65bf7db44b88e75"

  strings:
    $s1  = "culauncher.exe'Executable name of CUAssistant Launcher" fullword wide
    $s2  = "<image placement=\"appLogoOverride\" hint-crop=\"circle\" src=\"%s\"/>" fullword wide
    $s3  = "<text id=\"1\" hint-style=\"header\">%s</text>" fullword wide
    $s4  = "<text id=\"2\" hint-style=\"subheader\">%s</text>" fullword wide
    $s5  = "<action  imageUri=\"%s\" content=\"%s\" arguments=\"%s\" activationType=\"%s\"/>" fullword wide
    $s6  = "<action content=\"%s\" arguments=\"%s\" activationType=\"%s\"/>" fullword wide
    $s7  = "Your device must restart to complete the installation of security update. We will restart at %s. Please make sure to save your f" wide
    $s8  = "Your organization has requested a restart to complete the installation of security update. We will restart at %s. Please make su" wide
    $s9  = "Invalid packageVersion: %s" fullword wide
    $s10 = "Valid packageVersion: %s" fullword wide
    $s11 = "<image placement=\"hero\" src=\"%s\"/>" fullword wide
    $s12 = "Number of triggers in task %s is %d." fullword wide
    $s13 = "Trigger with type %d is disabled." fullword wide
    $s14 = "Checking current user session : State: %d" fullword wide
    $s15 = "pFailed to verify signature for %s" fullword wide
    $s16 = "Your device must restart to complete the installation of security update. Please make sure to save your files before restarting." wide
    $s17 = "Your organization has requested a restart to complete the installation of security update. Please make sure to save your files b" wide
    $s18 = "Starting qualauncher" fullword wide
    $s19 = "<toast launch=\"Remainder\">" fullword wide
    $s20 = "CUAssistant Reboot-Restart to install the latest Windows updates" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "34ab9ecd1566711ad1baa609e7db9a6b" and (8 of them)
    ) or (all of them)
}