rule _20160921_13e37e5857b4357c4b5f40a021143101_20160921_619a314e9bcc_2724 {
  meta:
    description = "datamaliciousorder - from files 20160921_13e37e5857b4357c4b5f40a021143101.js, 20160921_619a314e9bcca286c046dff250b54b6b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd94ae3a0c3b8dadcaba65cdd5f58ebd19d616ac5679af1b7891e5bf26889265"
    hash2       = "9f370548310908c52102d40d56781574ad404eafca7ac832d5e52d48f722bff5"

  strings:
    $s1 = "TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"BQb\";})(),(funct" ascii
    $s2 = "rn \"BQb\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Uo\";})(),(fu" ascii
    $s3 = "(function f000(){return \"Uo\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Qj\";})(),(function f000(){re" ascii
    $s4 = "h\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Wb\";})(),(function " ascii
    $s5 = "\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s6 = "n f000(){return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qz" ascii
    $s7 = "){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MJq\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}