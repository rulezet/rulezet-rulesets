rule _20160921_1c0508ced9fad1614d80fce90a3209ed_20160921_85b0b9490091_3470 {
  meta:
    description = "datamaliciousorder - from files 20160921_1c0508ced9fad1614d80fce90a3209ed.js, 20160921_85b0b94900915170fd854268d8d17fd4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e27406e32c891781b5403c718c4f32d67f6580cf6f952a30d0c6452ab9775a4c"
    hash2       = "02801a1fe1d3c30ef8c10eab40eabc26c88f8bc28e76e3aecbbb89d0981b21af"

  strings:
    $s1 = "turn \"RPt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})()," ascii
    $s2 = "n f000(){return \"GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(function f000(){return " ascii
    $s3 = "turn \"Kw\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(f" ascii
    $s4 = "unction f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){ret" ascii
    $s5 = "Pt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Zj\";})(),(function" ascii
    $s6 = "f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Qz" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}