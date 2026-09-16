rule _20160921_346ce24842d4c67049d4ae8a4ef57f0b_20160922_b22dda4c9fbc_1472 {
  meta:
    description = "datamaliciousorder - from files 20160921_346ce24842d4c67049d4ae8a4ef57f0b.js, 20160922_b22dda4c9fbc74ba5e251fc3110ada5a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24cea6347b33f54d332a2f5000d3f2841a3a09a1270f4da0da530495cac7ac0e"
    hash2       = "946b208e84c64dbffc7e1cb08a19f629639d795decea5bf8ddd08b34a59e5e59"

  strings:
    $s1  = "ction f000(){return \"Iq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DNa\";})(),(function f000(){retur" ascii
    $s2  = " \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"PTi\";})(),(fun" ascii
    $s3  = "n f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"" ascii
    $s4  = ";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f00" ascii
    $s5  = "eturn \"RPt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qa\";})()," ascii
    $s6  = "00(){return \"DNa\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\"" ascii
    $s7  = "n f000(){return \"DYx\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"" ascii
    $s8  = "unction f000(){return \"ZFe\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){ret" ascii
    $s9  = "000(){return \"QDg\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Sq" ascii
    $s10 = "(){return \"KXg\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Lp\";}" ascii
    $s11 = "eturn \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})()," ascii
    $s12 = "),(function f000(){return \"Wy\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Iq\";})(),(function f000(){" ascii
    $s13 = " f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"D" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}