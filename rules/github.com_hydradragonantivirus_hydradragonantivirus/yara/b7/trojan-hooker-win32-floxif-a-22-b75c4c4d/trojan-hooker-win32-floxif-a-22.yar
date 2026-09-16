rule Trojan_Hooker_Win32_Floxif_A_22 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Floxif.A_22.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c907d445b5e91460b26f3716fb3b9f265e22498d5a2efe1b4d75952990336841"

  strings:
    $x1  = "Flash Player - Debugkonsole5FSCommand angehalten (AllowScriptAccess ist '%s'): %s6Skript-URL angehalten (AllowScriptAccess ist '" wide
    $s2  = "Error attempting to execute IME command." fullword ascii
    $s3  = "Avvertenza: 403 - Vietato: %s!Avvertenza: 404 - Non trovato: %sAAvvertenza: 405 - Metodo non consentito, Tipo MIME non valido: %" wide
    $s4  = ";Legacy domain match encountered - %s is trying to access %s5-- Untrusted local SWFs may not contact the Internet.*-- Remote SWF" wide
    $s5  = "Warning: 502 - Bad Gateway: %s#Warning: 503 - Out of Resources: %s#Warning: 504 - Gateway Time-Out: %s-Warning: 505 - HTTP Versi" wide
    $s6  = "lai de passerelle : %s;Avertissement : 505 - Version HTTP non prise en charge : %s+Avertissement : connexion impossible, %s:%d7A" wide
    $s7  = "Proxy$358$private7http://www.macromedia.com/2005/actionscript/flash/proxy" fullword ascii
    $s8  = "Flash Player Debug Console0FSCommand halted (AllowScriptAccess is '%s'): %s1Script URL halted (AllowScriptAccess is '%s'): %s=Se" wide
    $s9  = "cter0Advertencia: FTP - error al abrir el archivo, %s5Advertencia: HTTP - error de petici" fullword wide
    $s10 = "Possibly incompatible version of dwlGina2.dll detected." fullword ascii
    $s11 = "n de Flash Player8Se ha detenido FSCommand (AllowScriptAccess es '%s'): %sMSe ha detenido el URL del archivo de comandos (AllowS" wide
    $s12 = "flash.system$372$private\"SecurityErrorEventType$379$private" fullword ascii
    $s13 = "Do you want to reboot Windows now ?=you must have administration rights to uninstall dwlgina2.dll" fullword wide
    $s14 = "Old version of dwlGina.dll detected" fullword ascii
    $s15 = "flash.display$366$private%flash.display:SWFLoaderInfo$protected\"flash.display:LoaderInfo$protected" fullword ascii
    $s16 = "loggerData<{z}>string<{z}>getset<{z}> <{!z!}>" fullword wide
    $s17 = "allUsersAppData<{z}>string<{z}>ppsv<{z}>" fullword wide
    $s18 = "Warning: Internet open error-Warning: Not a known player download type, %s*Warning: Port %d is outside allowed range.$Warning: R" wide
    $s19 = " Consulte http://www.macromedia.com/go/ac2e1eab para obtener m" fullword wide
    $s20 = "dwlgina2.dll was successfully installed." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}