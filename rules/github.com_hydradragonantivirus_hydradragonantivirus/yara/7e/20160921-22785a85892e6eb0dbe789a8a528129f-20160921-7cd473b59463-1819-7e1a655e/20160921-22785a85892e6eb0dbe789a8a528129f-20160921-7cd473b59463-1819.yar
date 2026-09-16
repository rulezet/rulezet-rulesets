rule _20160921_22785a85892e6eb0dbe789a8a528129f_20160921_7cd473b59463_1819 {
  meta:
    description = "datamaliciousorder - from files 20160921_22785a85892e6eb0dbe789a8a528129f.js, 20160921_7cd473b59463126782b9a6cfaae72835.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bd9f1cc39c45e7b6963f5eca04b26ef2eaf9c8005e5a0d5f12e868261ae58ca"
    hash2       = "0e3e3663f9696265255bc848bc98ec77487c491ee2a30b3085dbc10087b935c5"

  strings:
    $s1  = "eturn \"Tn\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Yz\";})(),(" ascii
    $s2  = "){return \"IAa\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";}" ascii
    $s3  = "ction f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Sq\";})(),(function f000(){retur" ascii
    $s4  = "IAa\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(functi" ascii
    $s5  = ";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"BQb\";})(),(function f0" ascii
    $s6  = "nction f000(){return \"Ml\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Oe\";})(),(function f000(){retur" ascii
    $s7  = "n f000(){return \"Oh\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"D" ascii
    $s8  = "{return \"Vj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(" ascii
    $s9  = "eturn \"Oe\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Sj\";})()," ascii
    $s10 = " f000(){return \"Wy\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}