import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_eSX_amMcCQb_5_2_Virus_Hijac_61 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.eSX@amMcCQb_5_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.eSX@amMcCQb_8_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.EuZ@aiy413e_10_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.EuZ@aiy413e_11_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.EuZ@aiy413e_15.vir, Virus.Hijack_Gen.Trojan.ShellObject.EuZ@aiy413e_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23a25cc2feec851e0d1dbcb3edabe0d02373f176b4526cdb3abd97795b5a5c4d"
    hash2       = "5847c0d50553d832c289b21658cf64bdae66267b2ef73b3751231791c076e525"
    hash3       = "c7f9226d258791bc3b7c2459e2e1764be913a0985a60ca6bcd67fadbbaf5462c"
    hash4       = "ba64fce50534b1583891982a16956c9a24ae91daea1668605d102620b6677b2d"
    hash5       = "cf617c50ba14391b1d4304d2d89eae47be73b674a501f2f2651cd50e46e58325"
    hash6       = "a51d302b290f4adb2da2151a0e108dc587a629823864d99310dcb2e56fb5feb3"

  strings:
    $x1  = "!!!!!fuk-tcpa!!!!!<?xml version=\"1.0\" encoding=\"utf-8\"?><Rules xmlns=\"urn:Rules\"><R Id=\"1000\" V=\"5\" DC=\"ESM\" EN=\"Of" ascii
    $s2  = "><S T=\"5\" F=\"ScopeName\" /></L><R><V V=\"XLDesktop Command Execution:534\" T=\"W\" /></R></O></R></O></R></O></F><F T=\"7\"><" ascii
    $s3  = "\"AND\"><L><O T=\"NE\"><L><S T=\"5\" F=\"ScopeName\" /></L><R><V V=\"XLDesktop Command Execution:532\" T=\"W\" /></R></O></L><R>" ascii
    $s4  = "b bix8d bix8f bix8h bix8j bix8l bojix bk8ux bcss8 c5n49\" /><UCSS T=\"2\" C=\"Command Usage\" S=\"Medium\" /><F T=\"3\"><O T=\"E" ascii
    $s5  = "gn2y bgn21 bujz1 bunl0 ide6g b0mo1\" /><UCSS T=\"2\" C=\"Command Usage\" S=\"Medium\" /><F T=\"3\"><O T=\"EQ\"><L><S T=\"1\" F=" ascii
    $s6  = "></O></F></S><C T=\"W\" I=\"0\" O=\"true\" N=\"SmbHumanHelpGetProductStringError\"><S T=\"6\" F=\"ContextData\" /></C><C T=\"W\"" ascii
    $s7  = "OobeWelcomeVideoHealth.Unexportable\" ATT=\"350d24c16a934c2d9734791ed7301d8e-73bafc90-ca43-424c-815a-63b076120b49-6725\" SP=\"Cr" ascii
    $s8  = " I=\"3\" O=\"true\" N=\"ContentNumber\"><S T=\"1\" F=\"ContentNumber\" /></C><T><S T=\"1\" /></T></R><R Id=\"510056\" V=\"0\" DC" ascii
    $s9  = "oCompleteInMillisecondsHighPrecision\" /></R></O></C><C T=\"B\" I=\"3\" O=\"false\"><S T=\"2\" F=\"Success\" /></C><C T=\"I32\" " ascii
    $s10 = " T=\"24\" F=\"Cipher Suite\" M=\"Ignore\" /></R></O></R></O></A></C><C T=\"W\" I=\"12\" O=\"true\" N=\"HashAlgorithm\"><A T=\"LA" ascii
    $s11 = "s=\"\"><RIS><RI N=\"Event\" /></RIS><S><UCSS T=\"1\" C=\"NexusTenantTokenResources\" S=\"Medium\" /><F T=\"2\"><O T=\"GE\"><L><S" ascii
    $s12 = "SCE\"><L><O T=\"COALESCE\"><L><S T=\"21\" F=\"Hash Algorithm\" M=\"Ignore\" /></L><R><S T=\"22\" F=\"Hash Algorithm\" M=\"Ignore" ascii
    $s13 = "L><R><O T=\"COALESCE\"><L><S T=\"23\" F=\"Hash Algorithm\" M=\"Ignore\" /></L><R><S T=\"24\" F=\"Hash Algorithm\" M=\"Ignore\" /" ascii
    $s14 = "CE\"><L><S T=\"21\" F=\"Key Size (bits)\" M=\"Ignore\" /></L><R><S T=\"22\" F=\"Key Size (bits)\" M=\"Ignore\" /></R></O></L><R>" ascii
    $s15 = "E\"><L><S T=\"23\" F=\"Key Size (bits)\" M=\"Ignore\" /></L><R><S T=\"24\" F=\"Key Size (bits)\" M=\"Ignore\" /></R></O></R></O>" ascii
    $s16 = "<C><S T=\"7\" /></C></C><C T=\"U32\" I=\"6\" O=\"false\" N=\"ErrorOnLoadingFlexValueNull\"><C><S T=\"8\" /></C></C><C T=\"U32\" " ascii
    $s17 = "\" R=\"120100\" /></S><C T=\"U16\" I=\"0\" O=\"true\" N=\"AppBuild\"><S T=\"1\" F=\"AppVersionBuild\" M=\"Ignore\" /></C><C T=\"" ascii
    $s18 = " O=\"true\" N=\"SqmUserId\"><S T=\"2\" F=\"SqmUidUser\" M=\"Ignore\" /></C><C T=\"W\" I=\"11\" O=\"true\" N=\"CID\"><S T=\"4\" F" ascii
    $s19 = "N=\"HttpResponseCode\"><S T=\"1\" F=\"HttpResponseCode\" /></C><C T=\"W\" I=\"1\" O=\"false\" N=\"ActivityCorrelationId\"><S T=" ascii
    $s20 = "\" /></C><C T=\"U16\" I=\"16\" O=\"true\" N=\"OfficeMajorVer\"><S T=\"1\" F=\"OfficeVersionMajor\" M=\"Ignore\" /></C><C T=\"U16" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "98dfd9b9e184a03c6ea488ca38f4797e" and (1 of ($x*) and 4 of them)
    ) or (all of them)
}