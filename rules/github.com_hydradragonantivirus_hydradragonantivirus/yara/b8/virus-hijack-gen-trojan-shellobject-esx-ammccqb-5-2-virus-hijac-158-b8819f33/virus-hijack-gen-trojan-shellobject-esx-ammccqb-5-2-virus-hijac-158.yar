import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_eSX_amMcCQb_5_2_Virus_Hijac_158 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.eSX@amMcCQb_5_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.EuZ@aiy413e_11_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.EuZ@aiy413e_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23a25cc2feec851e0d1dbcb3edabe0d02373f176b4526cdb3abd97795b5a5c4d"
    hash2       = "ba64fce50534b1583891982a16956c9a24ae91daea1668605d102620b6677b2d"
    hash3       = "a51d302b290f4adb2da2151a0e108dc587a629823864d99310dcb2e56fb5feb3"

  strings:
    $x1  = "!!!!!fuk-tcpa!!!!!<?xml version=\"1.0\" encoding=\"utf-8\"?><Rules xmlns=\"urn:Rules\"><R Id=\"120100\" V=\"3\" DC=\"SM\" T=\"Su" ascii
    $s2  = "=\"HasOpen\"><S T=\"1\" F=\"HasOpen\" M=\"Ignore\" /></C><C T=\"B\" I=\"25\" O=\"true\" N=\"BootCompleted\"><S T=\"1\" F=\"BootC" ascii
    $s3  = "s=\"\"><RIS><RI N=\"Event\" /></RIS><S><UCSS T=\"1\" C=\"NexusTenantTokenCharting\" S=\"Medium\" /><F T=\"2\"><O T=\"GE\"><L><S " ascii
    $s4  = "nID\" M=\"Ignore\" /></C><C T=\"U32\" I=\"8\" O=\"true\" N=\"GeoID\"><S T=\"2\" F=\"GeoID\" M=\"Ignore\" /></C><C T=\"W\" I=\"9" ascii
    $s5  = "lns=\"\"><RIS><RI N=\"Event\" /></RIS><S><UCSS T=\"1\" C=\"NexusTenantTokenAugLoop\" S=\"Medium\" /><F T=\"2\"><O T=\"GE\"><L><S" ascii
    $s6  = "-b37f-4635-8054-5c133fcd04c4-6587\" SP=\"CriticalBusinessImpact\" DCa=\"PSP\" xmlns=\"\"><S><UCSS T=\"1\" C=\"Click-To-Run Task " ascii
    $s7  = "\" /></C><C T=\"W\" I=\"1\" O=\"true\" N=\"EventContract\"><S T=\"2\" F=\"EventContract\" M=\"Ignore\" /></C><C T=\"U64\" I=\"2" ascii
    $s8  = " F=\"EventData\" /></C><C T=\"W\" I=\"5\" O=\"false\" N=\"EventContractInfo\"><S T=\"2\" F=\"EventContractInfo\" /></C><C T=\"W" ascii
    $s9  = "></C><C T=\"D\" I=\"3\" O=\"false\" N=\"EventSampleRate\"><V V=\"1.0\" T=\"D\" /></C><C T=\"W\" I=\"4\" O=\"false\" N=\"EventDat" ascii
    $s10 = " F=\"EventContractInfo\" /></C><C T=\"W\" I=\"6\" O=\"false\" N=\"EventTypeInfo\"><S T=\"2\" F=\"EventTypeInfo\" /></C><C T=\"W" ascii
    $s11 = "\"2\"><O T=\"GE\"><L><S T=\"1\" F=\"EventSamplingPolicy\" /></L><R><V V=\"191\" T=\"U8\" /></R></O></F></S><C T=\"W\" I=\"0\" O=" ascii
    $s12 = "\"true\" N=\"EventContract\"><S T=\"2\" F=\"EventContract\" M=\"Ignore\" /></C><C T=\"U64\" I=\"2\" O=\"false\" N=\"EventFlags\"" ascii
    $s13 = "Monitorable Unexpected Assert\" /><F T=\"2\"><O T=\"AND\"><L><O T=\"AND\"><L><O T=\"AND\"><L><O T=\"AND\"><L><O T=\"NE\"><L><S T" ascii
    $s14 = "S><C T=\"W\" I=\"0\" O=\"false\" N=\"EventName\"><S T=\"2\" F=\"EventName\" /></C><C T=\"W\" I=\"1\" O=\"true\" N=\"EventContrac" ascii
    $s15 = "=\"2\"><O T=\"GE\"><L><S T=\"1\" F=\"EventSamplingPolicy\" /></L><R><V V=\"191\" T=\"U8\" /></R></O></F></S><C T=\"W\" I=\"0\" O" ascii
    $s16 = "ue\" N=\"EventID\"><S T=\"11\" F=\"ULS_Tag\" M=\"Ignore\" /></C><C T=\"W\" I=\"4\" O=\"true\" N=\"Severity\"><S T=\"11\" F=\"ULS" ascii
    $s17 = "ntSampleRate\"><V V=\"1.0\" T=\"D\" /></C><C T=\"W\" I=\"4\" O=\"false\" N=\"EventData\"><S T=\"2\" F=\"EventData\" /></C><C T=" ascii
    $s18 = "lBusinessImpact\" DCa=\"PSP\" xmlns=\"\"><S><UCSS T=\"1\" C=\"Click-To-Run UpSup Telemetry\" S=\"Verbose Medium Monitorable Unex" ascii
    $s19 = "C><C T=\"W\" I=\"7\" O=\"false\" N=\"EventDataClassificationInfo\"><S T=\"2\" F=\"EventDataClassificationInfo\" /></C><C T=\"W\"" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "98dfd9b9e184a03c6ea488ca38f4797e" and (1 of ($x*) and 4 of them)
    ) or (all of them)
}