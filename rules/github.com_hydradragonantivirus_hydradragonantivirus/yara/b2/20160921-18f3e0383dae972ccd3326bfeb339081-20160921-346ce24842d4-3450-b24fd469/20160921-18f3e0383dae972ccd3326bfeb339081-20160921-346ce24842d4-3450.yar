rule _20160921_18f3e0383dae972ccd3326bfeb339081_20160921_346ce24842d4_3450 {
  meta:
    description = "datamaliciousorder - from files 20160921_18f3e0383dae972ccd3326bfeb339081.js, 20160921_346ce24842d4c67049d4ae8a4ef57f0b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "350a94fd53479bde96c18236897fe9846647bd4d4471ff812cc45a165d90a9d0"
    hash2       = "24cea6347b33f54d332a2f5000d3f2841a3a09a1270f4da0da530495cac7ac0e"

  strings:
    $s1 = "),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"ZFe\";})(),(function f000(" ascii
    $s2 = ",(function f000(){return \"DNa\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn\";})(),(function f000()" ascii
    $s3 = "){return \"Lp\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Go\";})" ascii
    $s4 = " f000(){return \"ZFe\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MM" ascii
    $s5 = "tion f000(){return \"PTs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Do\";})(),(function f000(){return " ascii
    $s6 = "nction f000(){return \"Nv\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Yz\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}