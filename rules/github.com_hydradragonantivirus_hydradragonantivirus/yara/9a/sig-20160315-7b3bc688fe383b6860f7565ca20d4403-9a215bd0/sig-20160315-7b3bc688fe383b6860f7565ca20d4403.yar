rule sig_20160315_7b3bc688fe383b6860f7565ca20d4403 {
  meta:
    description = "datamaliciousorder - file 20160315_7b3bc688fe383b6860f7565ca20d4403.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce5ac37128397a36348d22c3386afa84b9beb1132ffc39b534d884d66c0a726e"

  strings:
    $s1  = "while (SZVC.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s2  = "cCDzsiEYKxZ = WScript[JSTSMsndoT + jLeitvLOf + NQHVIjoSYAC + TQjDihNHMzW + fuOHXfhDeM + nDts + nlJ](SwQp + Ltcrl + WFsgv + PbTh " ascii
    $s3  = "function bmbIRljBi(OszhGWGNjywyR){WshShell[HEouiD](OszhGWGNjywyR, 0, 0);}" fullword ascii
    $s4  = "+ HoPe + GfndNjRvkNITzqI);" fullword ascii
    $s5  = "function tJiufgLMUSZqE(n){return turJTQY + VXDTSGLS + UtawdJStgmZmjXj + IeiumEMGMquQV + DGdbSyh + RbOwvCbWRK + YYZE + IDiP + AjU" ascii
    $s6  = " + IaNpxaiWWrAaZl + jLZchbp, false);" fullword ascii
    $s7  = "function tJiufgLMUSZqE(n){return turJTQY + VXDTSGLS + UtawdJStgmZmjXj + IeiumEMGMquQV + DGdbSyh + RbOwvCbWRK + YYZE + IDiP + AjU" ascii
    $s8  = "SZVC[zHZaqhpmcGROCwn + jQMihc](ceJN + yEuyWBJRv, Hcz + MwJtcbB + iDtiAQwFT + hRgbUKjaoojOB + JHoKhHHQLPtzW + lnPueS + zQkywRpCpF" ascii
    $s9  = "var HoPe = \"r\";" fullword ascii
    $s10 = "var riImwGoeBZhdsH = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}