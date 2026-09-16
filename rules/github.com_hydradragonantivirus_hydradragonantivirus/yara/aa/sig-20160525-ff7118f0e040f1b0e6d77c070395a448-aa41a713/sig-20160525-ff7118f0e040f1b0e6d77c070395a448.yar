rule sig_20160525_ff7118f0e040f1b0e6d77c070395a448 {
  meta:
    description = "datamaliciousorder - file 20160525_ff7118f0e040f1b0e6d77c070395a448.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c9e392a85ad5e63010471b620a7d12c34dbe0a0cd3bd3efdae0250f63a0d39ac"

  strings:
    $s1  = " + Math.round((Math.pow(Math.sin(542), 2) + Math.pow(Math.cos(542), 2) - 1))-515)) llGqZAhqlTuZXuONflFfRUrp += nw(eQvugU);else i" ascii
    $s2  = "n(575), 2) + Math.pow(Math.cos(575), 2) - 1))-479) | nyzmasuIN;eQvugU = cHWUKcREQusTpeiZyAJhd>> (683 + Math.round((Math.pow(Math" ascii
    $s3  = ".sin(178), 2) + Math.pow(Math.cos(178), 2) - 1))-667) & 0xff;WwhXyqD = cHWUKcREQusTpeiZyAJhd>> (459 + Math.round((Math.pow(Math." ascii
    $s4  = "function QlbVQTVj(UpkfxkzIgOfWP) {var asOZIsbFWUg = vgtvdFQW.join(hYjfwdwdb[0]);var eQvugU, WwhXyqD, uuwDCuUe, PoDbfSygkrOeL, Lp" ascii
    $s5  = "function dODYaYRUPWTnkGhmed(bQiJGedhgzibhZDQCRt,dgICcbhbpyd){return bQiJGedhgzibhZDQCRt.charAt(dgICcbhbpyd);}" fullword ascii
    $s6  = "function QlbVQTVj(UpkfxkzIgOfWP) {var asOZIsbFWUg = vgtvdFQW.join(hYjfwdwdb[0]);var eQvugU, WwhXyqD, uuwDCuUe, PoDbfSygkrOeL, Lp" ascii
    $s7  = "function YshQBUJcEWCbhEJknwFhWLqL(LJEuSBvXzXdMKCTRUlMeY,sDewdgDfzNHBuqnS,OasNbiUwzGUeuBIqUjm){return String.fromCharCode(LJEuSBv" ascii
    $s8  = "ile (uNWwwaXVxgS < UpkfxkzIgOfWP.length);return llGqZAhqlTuZXuONflFfRUrp;}" fullword ascii
    $s9  = "+= hcOcToXMSLHOTaLlcb(eQvugU, WwhXyqD);else llGqZAhqlTuZXuONflFfRUrp += YshQBUJcEWCbhEJknwFhWLqL(eQvugU, WwhXyqD, uuwDCuUe);} wh" ascii
    $s10 = "function HSeCHqIywtHeS(fCmfziHaK,QocksNmZvVFvvEJVgBKvqE){return fCmfziHaK.indexOf(QocksNmZvVFvvEJVgBKvqE);}" fullword ascii
    $s11 = "function nw(ESWJoAHTNq){return String.fromCharCode(ESWJoAHTNq);}" fullword ascii
    $s12 = "function YshQBUJcEWCbhEJknwFhWLqL(LJEuSBvXzXdMKCTRUlMeY,sDewdgDfzNHBuqnS,OasNbiUwzGUeuBIqUjm){return String.fromCharCode(LJEuSBv" ascii
    $s13 = "function hcOcToXMSLHOTaLlcb(RAlDeKlvmQtpWMKZrHvZuBoE,DemJCakfonVc){return String.fromCharCode(RAlDeKlvmQtpWMKZrHvZuBoE,DemJCakfo" ascii
    $s14 = "function hcOcToXMSLHOTaLlcb(RAlDeKlvmQtpWMKZrHvZuBoE,DemJCakfonVc){return String.fromCharCode(RAlDeKlvmQtpWMKZrHvZuBoE,DemJCakfo" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}