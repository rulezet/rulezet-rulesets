rule _20160921_22785a85892e6eb0dbe789a8a528129f_20160922_9d6af2734812_4716 {
  meta:
    description = "datamaliciousorder - from files 20160921_22785a85892e6eb0dbe789a8a528129f.js, 20160922_9d6af27348126e594fbe29c3cf568591.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bd9f1cc39c45e7b6963f5eca04b26ef2eaf9c8005e5a0d5f12e868261ae58ca"
    hash2       = "3634189c93f3a76e0a4df72e631f0715b4b71427c157ca5fe116252ca00f1d9b"

  strings:
    $s1 = "eturn \"ZFe\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"NBs\";})()," ascii
    $s2 = ";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"RPt\";})(),(function f0" ascii
    $s3 = "ction f000(){return \"ZFe\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TRc\";})(),(function f000(){retur" ascii
    $s4 = "function f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Vj\";})(),(function f000(){re" ascii
    $s5 = "){return \"Qa\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}