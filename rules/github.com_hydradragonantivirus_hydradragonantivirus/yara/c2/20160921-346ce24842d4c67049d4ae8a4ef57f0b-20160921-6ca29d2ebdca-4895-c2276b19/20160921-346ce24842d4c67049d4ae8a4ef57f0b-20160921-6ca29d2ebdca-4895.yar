rule _20160921_346ce24842d4c67049d4ae8a4ef57f0b_20160921_6ca29d2ebdca_4895 {
  meta:
    description = "datamaliciousorder - from files 20160921_346ce24842d4c67049d4ae8a4ef57f0b.js, 20160921_6ca29d2ebdcaa2724b801c02414faf7f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24cea6347b33f54d332a2f5000d3f2841a3a09a1270f4da0da530495cac7ac0e"
    hash2       = "b810435d98ebab77ad9d2cd316e2a0c0211b0941d86cbfa6c0e753732c6d3b15"

  strings:
    $s1 = "{return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"ZFe\";}" ascii
    $s2 = "f000(){return \"Ot\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"OUx" ascii
    $s3 = "on f000(){return \"Do\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TRc\";})(),(function f000(){return " ascii
    $s4 = "nction f000(){return \"DNa\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Rh\";})(),(function f000(){retu" ascii
    $s5 = "f000(){return \"GGn\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Qa" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}