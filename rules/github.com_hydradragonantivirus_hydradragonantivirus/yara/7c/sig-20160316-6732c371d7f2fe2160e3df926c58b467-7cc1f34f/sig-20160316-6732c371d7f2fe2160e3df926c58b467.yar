rule sig_20160316_6732c371d7f2fe2160e3df926c58b467 {
  meta:
    description = "datamaliciousorder - file 20160316_6732c371d7f2fe2160e3df926c58b467.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "798088a24dd59e688abead2b5a107bb0adf5cca95bdd0483579ca6f6d8a10714"

  strings:
    $s1 = "while (qHBTqgHRzIFM[PUCqMMptPPalFUs + WZRtfJFtbuBt + wwKlptl + fwjJFeJLQDPTT + ZSqbczJmYIFsM] < 4 ) {WScript[VVBIMs + nfsZ](1000" ascii
    $s2 = "while (qHBTqgHRzIFM[PUCqMMptPPalFUs + WZRtfJFtbuBt + wwKlptl + fwjJFeJLQDPTT + ZSqbczJmYIFsM] < 4 ) {WScript[VVBIMs + nfsZ](1000" ascii
    $s3 = "qHBTqgHRzIFM[uJmjscMiwxysL + jfGSwhLn](qHOnigZY, KljkmdhNbjUnLMO + FuadgaBS + dxzCTH + nvzrHZYqSuQX + GtWWqCS + yeEhrGB + kFwFfp" ascii
    $s4 = "ehjXcIu + JGoMtpXCEh, false);" fullword ascii
    $s5 = "function lsGaUmjTu(WrFEXuJZFlvJ){JupBwVffTgZlaOm[EXEFCj + QQncyG](WrFEXuJZFlvJ, 0, 0);}" fullword ascii
    $s6 = "function Nik(n){return geQYNMcDBniN + ruIbQ + IKLiEXoE + lMKCzGpFbP + IQcpDgFvLaYyQw + BKvmaOMfsRnTGc;}" fullword ascii
    $s7 = "var AmDihYPwFpn = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}