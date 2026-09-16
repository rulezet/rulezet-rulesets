rule _20160921_0466c7255c8e70587363e07e045d3c4a_20160921_073115e7f89d_4186 {
  meta:
    description = "datamaliciousorder - from files 20160921_0466c7255c8e70587363e07e045d3c4a.js, 20160921_073115e7f89d0b69957e5f4053125e5f.js, 20160921_25c11e2eab44b5e0380e0bd805a72790.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23a4fdb08cf486e569a48a599a4a2c53d91892166b2194b7066e39c535723f8f"
    hash2       = "e1c8736261480d3d6df844d8e7fb92f64f1dc2bf84561d1b707e82daa456fef1"
    hash3       = "912d9aec3079fb6a2e4f83d3826286707a52a653de6ec6eede9711d5b416a790"

  strings:
    $s1 = "){return \"Ot\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Yi\";})" ascii
    $s2 = "n f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"G" ascii
    $s3 = "000(){return \"TKl\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"XTn" ascii
    $s4 = "tion f000(){return \"XTn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Kw\";})(),(function f000(){return " ascii
    $s5 = "\"GGn\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}