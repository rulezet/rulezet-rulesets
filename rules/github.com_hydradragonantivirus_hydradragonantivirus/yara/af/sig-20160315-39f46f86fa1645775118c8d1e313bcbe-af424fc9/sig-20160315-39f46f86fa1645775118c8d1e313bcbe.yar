rule sig_20160315_39f46f86fa1645775118c8d1e313bcbe {
  meta:
    description = "datamaliciousorder - file 20160315_39f46f86fa1645775118c8d1e313bcbe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12bb39eb90e1e4e56860ced5a6eda73057f7229f00687c059698b46fb4204b0c"

  strings:
    $s1 = "function rWCBUfVxUJHUKfx(vGrCOuVsftmk){WshShell[XFOfhYBMi + kahLQ](vGrCOuVsftmk, 0, 0);}" fullword ascii
    $s2 = "while (ALIuxlqkJ.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "function eAnHWBa(n){return wblbKxwdGLHzWjO + hdFhuxMCCEXt + Fyuqx + sLVymJVlXCL + miJW + mzLGmhOBl;}" fullword ascii
    $s4 = "ALIuxlqkJ[LkU + YEITFRLgUHIX](fblSGc, YvqTsLvCbyVr + OkqHCgmQUHFlEX + uAwJFzfVEqCGU + GeJaMCCM + HOlPLZBzyvOBVS + hujDyYuOYaL + " ascii
    $s5 = "var gkytKwDXrhItrF = new Date();" fullword ascii
    $s6 = "mffx + qDQOxaLIYBiz + HcekOweuCaNV + bWxTMwp + ymrmgqNhG + rdzfeK + vDDSEt, false);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}