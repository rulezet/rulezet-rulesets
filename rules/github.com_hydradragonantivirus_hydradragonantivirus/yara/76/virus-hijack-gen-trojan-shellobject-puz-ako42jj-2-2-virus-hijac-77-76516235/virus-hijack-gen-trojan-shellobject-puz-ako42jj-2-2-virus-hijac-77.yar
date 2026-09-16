import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_puZ_aKo42Jj_2_2_Virus_Hijac_77 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.puZ@aKo42Jj_2_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.puZ@aKo42Jj_3_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.puZ@aKo42Jj_4_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.puZ@aKo42Jj_5_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f2abb00c3b99fca9398ac1b5865eeca43473df46a831adad1c18205865005e0"
    hash2       = "e017175bbb5b8bf16f81791bbf9e401d9c4a0fa91df6f2b0e2a8efb20546fd75"
    hash3       = "07a4111d358e8cddb418a922731ac19176f72aeb437b9f71de41fa73b61a9d7f"
    hash4       = "766efc1c6387b1f63c6b26c153e828d991f36f13c8f5ba951abfc7d78fb881d5"

  strings:
    $s1  = "                <add name=\"Request Processing Events\" type=\"System.Web.Management.WebRequestEvent,System.Web,Version=2.0.0.0," ascii
    $s2  = "                <add name=\"Request Processing Errors\" type=\"System.Web.Management.WebRequestErrorEvent,System.Web,Version=2.0" ascii
    $s3  = "<!-- the root web configuration file -->" fullword ascii
    $s4  = "                <add name=\"Failure Audits\" type=\"System.Web.Management.WebFailureAuditEvent,System.Web,Version=2.0.0.0,Cultur" ascii
    $s5  = "                <add name=\"Success Audits\" type=\"System.Web.Management.WebSuccessAuditEvent,System.Web,Version=2.0.0.0,Cultur" ascii
    $s6  = "                <add name=\"Infrastructure Errors\" type=\"System.Web.Management.WebErrorEvent,System.Web,Version=2.0.0.0,Cultur" ascii
    $s7  = "1Failed to generate type library, missing midl.exe" fullword wide
    $s8  = "                <add name=\"Request Processing Events\" type=\"System.Web.Management.WebRequestEvent,System.Web,Version=2.0.0.0," ascii
    $s9  = "            <result type=\"System.Web.Mobile.MobileCapabilities, System.Web.Mobile, Version=2.0.0.0, Culture=neutral, PublicKeyT" ascii
    $s10 = "                <add name=\"Application Lifetime Events\" type=\"System.Web.Management.WebApplicationLifetimeEvent,System.Web,Ve" ascii
    $s11 = "        <compilation tempDirectory=\"\" debug=\"false\" strict=\"false\" explicit=\"true\" batch=\"true\" batchTimeout=\"900\" m" ascii
    $s12 = "<description>Java(TM) SE jmap process</description>" fullword ascii
    $s13 = "                <control name=\"System.Web.UI.MobileControls.Command\" adapter=\"System.Web.UI.MobileControls.Adapters.ChtmlComm" ascii
    $s14 = "                <control name=\"System.Web.UI.MobileControls.Command\" adapter=\"System.Web.UI.MobileControls.Adapters.WmlComman" ascii
    $s15 = "                <control name=\"System.Web.UI.MobileControls.Command\" adapter=\"System.Web.UI.MobileControls.Adapters.WmlComman" ascii
    $s16 = "                <control name=\"System.Web.UI.MobileControls.Command\" adapter=\"System.Web.UI.MobileControls.Adapters.ChtmlComm" ascii
    $s17 = "                <control name=\"System.Web.UI.MobileControls.Command\" adapter=\"System.Web.UI.MobileControls.Adapters.HtmlComma" ascii
    $s18 = "                <control name=\"System.Web.UI.MobileControls.Command\" adapter=\"System.Web.UI.MobileControls.Adapters.HtmlComma" ascii
    $s19 = "                <control name=\"System.Web.UI.MobileControls.Command\" adapter=\"System.Web.UI.MobileControls.Adapters.XhtmlAdap" ascii
    $s20 = "                <control name=\"System.Web.UI.MobileControls.Command\" adapter=\"System.Web.UI.MobileControls.Adapters.XhtmlAdap" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "53d02dee8a3558f2a2295b34eb0d6374" and (8 of them)
    ) or (all of them)
}