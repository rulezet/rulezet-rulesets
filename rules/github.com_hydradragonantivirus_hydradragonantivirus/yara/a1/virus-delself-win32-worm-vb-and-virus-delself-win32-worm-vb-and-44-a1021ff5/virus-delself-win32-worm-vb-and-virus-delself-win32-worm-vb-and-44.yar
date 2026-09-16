import "pe"
rule _Virus_Delself_Win32_Worm_VB_AND_Virus_Delself_Win32_Worm_VB_AND_44 {
  meta:
    description = "datamaliciousorder - from files Virus.Delself_Win32.Worm.VB.AND.vir, Virus.Delself_Win32.Worm.VB.AND_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b0b524939b546bf9ac84f8af3eea669520d1410bc1de97a8d9058b19244a92f"
    hash2       = "d94d1e819fc104afc753978cac062e125d4bcbc4b0b6515c8424d082c4f9f461"

  strings:
    $s1  = "Nonce passed on the command line is not correctly encoded" fullword ascii
    $s2  = "XDer opstod en fejl ved operativsystemet under installation. Download Google Chrome igen.jW" fullword wide
    $s3  = "Timed out waiting for MSI mutex." fullword ascii
    $s4  = "Device trust key rotation failed. Could not send public key to DM server." fullword ascii
    $s5  = " jednou.PMae'r archif gosodwr wedi'i lygru neu'n annilys. Lawrlwythwch Google Chrome eto.OInstallationsarkivet er beskadiget ell" wide
    $s6  = "WebCompiler is a Trademark of Oakley Data Services" fullword wide
    $s7  = " jednou.DBu gwall system weithredu wrth osod. Lawrlwythwch Google Chrome eto." fullword wide
    $s8  = "request headers: " fullword ascii
    $s9  = "response headers: " fullword ascii
    $s10 = "fico mDNS.MSissetuleku reegel Google Chrome'i beetaversioonile mDNS-liikluse lubamiseks." fullword wide
    $s11 = "Setting proxy " fullword ascii
    $s12 = " run under Win32" fullword ascii
    $s13 = "Oakley Data Services" fullword wide
    $s14 = " 1998 Oakley Data Services" fullword wide
    $s15 = "nstalleerd voor alle gebruikers op je computer." fullword wide
    $s16 = "unaru.BGoogle Chrome har redan installerats f" fullword wide
    $s17 = "tInstalazioak huts egin du zehaztu gabeko errore batengatik. Google Chrome abian bada, itxi ezazu eta saiatu berriro.m" fullword wide
    $s18 = ".sYou do not have appropriate rights for system-level installation. Try running the installer again as Administrator." fullword wide
    $s19 = "nYou do not have appropriate rights for system-level install. Try running the installer again as Administrator." fullword wide
    $s20 = "ltig. Lade Google Chrome erneut herunter." fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "634dedd3d9e87ec17ec29bd42899975e" and (8 of them)
    ) or (all of them)
}