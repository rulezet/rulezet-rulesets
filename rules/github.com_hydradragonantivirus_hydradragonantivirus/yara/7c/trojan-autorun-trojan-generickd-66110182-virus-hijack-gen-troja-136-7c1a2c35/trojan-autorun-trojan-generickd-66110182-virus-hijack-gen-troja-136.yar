import "pe"
rule _Trojan_Autorun_Trojan_GenericKD_66110182_Virus_Hijack_Gen_Troja_136 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Trojan.GenericKD.66110182.vir, Virus.Hijack_Gen.Trojan.ShellObject.tyZ@aag1Gcl_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.tyZ@aSgChKg_1_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.tyZ@aSgChKg_2_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.tyZ@aSgChKg_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c7dca12b40c50414166738737c1ce14d6496ef954bf1b90e940cfd0f026485c"
    hash2       = "ca1a076dd3404ec2588702b0e5f3e0813f25b085bb98985296d3afa815230a22"
    hash3       = "ed76141284fb07fe8c33040d0b95b54c78bbf494dfac4c802d2913d2c549d8f8"
    hash4       = "059d91e0e7cb9d51bc52994c97cee16e70552af7a98aa0023df6e1b37db8e735"
    hash5       = "d71a2029eb719207f5dea158cf32d33b5c2b63e85c28cbea668717de784f2058"

  strings:
    $x1  = "Authorization: Passport1.4 OrgVerb=GET,OrgURL=http://messenger.msn.com,sign-in=%s,pwd=%s,%s" fullword ascii
    $s2  = "Authorization: Passport1.4 OrgVerb=GET,OrgURL=http%%3A%%2F%%2Fmessenger%%2Emsn%%2Ecom,sign-in=%s,pwd=%s,%s" fullword ascii
    $s3  = "<?xml version=\"1.0\"?><provision key=\"messenger\" name=\"messenger\"><user uri=\"sip:%s@%s\" account=\"%s\" name=\"%s\" passwo" ascii
    $s4  = "<?xml version=\"1.0\"?><provision key=\"messenger\" name=\"messenger\"><user uri=\"sip:%s@%s\" account=\"%s\" name=\"%s\" passwo" ascii
    $s5  = "Messenger ISensLogon Subscription" fullword wide
    $s6  = "<HTML><HEAD><META HTTP-EQUIV=\"REFRESH\" CONTENT=\"0; URL=" fullword ascii
    $s7  = "m=\"voice.net\" /><sipsrv addr=\"%s\" protocol=\"%s\" %s role=\"proxy\"><session party=\"first\" type=\"pc2ph\" /></sipsrv></pro" ascii
    $s8  = "Global\\MSMSGS.EXE Event" fullword wide
    $s9  = "  <service name=\"%s\">" fullword wide
    $s10 = "Messenger ISensNetwork Subscription" fullword wide
    $s11 = "<TEXT xml:space=\"preserve\" enc=\"utf-8\">%s</TEXT>" fullword ascii
    $s12 = "<PHONE pri=\"1\"><LOC>%s</LOC><NUM>%s</NUM></PHONE><TEXT xml:space=\"preserve\" enc=\"utf-8\">%s</TEXT>" fullword ascii
    $s13 = "System policy has disabled Messenger ((HKCU/HKLM)Software\\Policies\\Microsoft\\Messenger\\Client\\PreventRun).  Messenger has s" wide
    $s14 = "System policy has disabled auto sign-in of Messenger ((HKCU/HKLM)Software\\Policies\\Microsoft\\Messenger\\Client\\PreventAutoRu" wide
    $s15 = "import:" fullword wide
    $s16 = "UserMicrosoft RTC Instant Messaging" fullword wide
    $s17 = "(MSN/Windows) Messenger Service" fullword wide
    $s18 = "Messenger Initiated Session" fullword wide
    $s19 = "Account Info Pane" fullword wide
    $s20 = "Connection Method" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "da610ca700d3fcd07221889fd01b5be9" and (1 of ($x*) and 4 of them)
    ) or (all of them)
}