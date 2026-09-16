rule _20160921_8aaa596582e26eec62319f01660d922b_20160921_b2867778b87a_1510 {
  meta:
    description = "datamaliciousorder - from files 20160921_8aaa596582e26eec62319f01660d922b.js, 20160921_b2867778b87ab68774c77840f21eaed0.js, 20160922_2c550b6efe6ec163893e1c555d256b4e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "345c67f8d573844507dfad7f05cf340f1a2bb19331e3e0d242c508445594aac6"
    hash2       = "ae46b7285b241d53af42d1248b27d7d1186f12901d6fc0284d48665a3b217777"
    hash3       = "deabc297df80ed9899178f4a02c9538b2fe3ee2038528e07da89655f0d68b1a1"

  strings:
    $s1  = "function f000(){return \"ZGq\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qa\";})(),(function f000(){re" ascii
    $s2  = "eturn \"MBb\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"ZGq\";})()" ascii
    $s3  = "ction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){retur" ascii
    $s4  = ")(),(function f000(){return \"TKl\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Zj\";})(),(function f000" ascii
    $s5  = "(),(function f000(){return \"ZGq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(function f000(" ascii
    $s6  = "n\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function " ascii
    $s7  = "n \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"SGs\";})(),(fun" ascii
    $s8  = "000(){return \"Qz\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"OMd" ascii
    $s9  = "urn \"KDh\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"QDg\";})()," ascii
    $s10 = "ion f000(){return \"ZGq\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s11 = "ion f000(){return \"ZGq\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s12 = "000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"KD" ascii
    $s13 = "nction f000(){return \"Qz\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Zj\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}