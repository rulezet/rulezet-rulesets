rule _20160921_6748b4ad3c83a7c4aeacfc0817a81797_20160922_f0d656e55be0_5333 {
  meta:
    description = "datamaliciousorder - from files 20160921_6748b4ad3c83a7c4aeacfc0817a81797.js, 20160922_f0d656e55be0c93b2b5e1f0eda45da9a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f5e85f2791984d17e00bdb2b7163597d52bf88d9da5a0caedc977a31026ee9f7"
    hash2       = "276c24e399a13bf7907294578800d75620fb48bcd34bc84b9d92448375c72d37"

  strings:
    $s1 = "){return \"Vu\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"WIj\";})(" ascii
    $s2 = "(),(function f000(){return \"WIj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Kw\";})(),(function f000(" ascii
    $s3 = "ion f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return" ascii
    $s4 = "urn \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(f" ascii
    $s5 = " f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}