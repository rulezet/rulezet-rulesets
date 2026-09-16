import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_fCY_aijlKSl_11_2_Virus_Hija_119 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.fCY@aijlKSl_11_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.fWW@a0tiwSg_1_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.u8Z@aqsS8zj_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3ff050f8c515427f4ec6bc25fba2854446a722ee419f6962bb8bdaa99ecfc36"
    hash2       = "89a1af3a2afece7e197443049ab929855cd0cd7fe16b60c37a8af1f4d76aa1db"
    hash3       = "58df3c604e68ae72afda237905fca3f890c4271bcdba6b0b4db5b6c510a84bf0"

  strings:
    $s1  = "GetPinProductId - setup data from PIN is corrupted." fullword wide
    $s2  = "ProcessTASilentResult finished." fullword wide
    $s3  = "PipcHybrid::OnPinRedemptionError: Error occurred; status=0x%x, httpStatusCode=%d, wzError=%s" fullword wide
    $s4  = "RedemptionApi::SendPinRedemptionRequest: Performing PIN redemption request; clientTransactionId=%s, consentToEmailPromotion=%i, " wide
    $s5  = "RedemptionApi::SendRedemptionRequest: Converted ServiceRequestCustom status 0x%8X to failed hr" fullword wide
    $s6  = "GetGenuineTicket finished succesfully." fullword wide
    $s7  = "GetOlsBindingInfo finished succesfully." fullword wide
    $s8  = "Firstrun: SetEulaAccepted() complete." fullword wide
    $s9  = "Firstrun: Sign-in skipped by user." fullword wide
    $s10 = "Firstrun: Initialization complete." fullword wide
    $s11 = "Firstrun: Showing welcome view." fullword wide
    $s12 = "PipcHybrid::OnPinRedemptionSuccess: Completed successfully; hr=%d" fullword wide
    $s13 = "GetPinProductId finished succesfully." fullword wide
    $s14 = "?Finish@Frame@MsoCF@@YGXXZ" fullword ascii
    $s15 = "?Start@Frame@MsoCF@@YGXXZ" fullword ascii
    $s16 = "?TerminateTheApp@Frame@MsoCF@@YGXXZ" fullword ascii
    $s17 = "?CreateTheApp@Frame@MsoCF@@YGXAAUCreateTheAppArgs@12@@Z" fullword ascii
    $s18 = "?TheApp@Frame@MsoCF@@YGPAUAFrameApp@2@XZ" fullword ascii
    $s19 = "Exiting, since we're running in an OOBE mode, and Office setup is running" fullword wide
    $s20 = "@Firstrun: Starting background tasks." fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "b941ddedcc51e5706d41335adb4e6b2a" and (8 of them)
    ) or (all of them)
}