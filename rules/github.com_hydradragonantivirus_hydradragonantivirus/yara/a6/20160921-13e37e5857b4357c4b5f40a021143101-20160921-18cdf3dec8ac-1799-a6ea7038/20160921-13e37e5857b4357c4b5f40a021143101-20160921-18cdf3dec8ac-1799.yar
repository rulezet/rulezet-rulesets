rule _20160921_13e37e5857b4357c4b5f40a021143101_20160921_18cdf3dec8ac_1799 {
  meta:
    description = "datamaliciousorder - from files 20160921_13e37e5857b4357c4b5f40a021143101.js, 20160921_18cdf3dec8ac4b7697e775bc56ddeba9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd94ae3a0c3b8dadcaba65cdd5f58ebd19d616ac5679af1b7891e5bf26889265"
    hash2       = "1a1aa090c906360f52952b29d512b8c450c7e8c8cff28bc6fded6af15377b37c"

  strings:
    $s1  = "})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vu\";})(),(function f000(" ascii
    $s2  = "{return \"WIj\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";}" ascii
    $s3  = "eturn \"Wb\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"OUx\";})()," ascii
    $s4  = "function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Nx\";})(),(function f000(){retu" ascii
    $s5  = "n \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Oh\";})(),(func" ascii
    $s6  = "Ij\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(functio" ascii
    $s7  = "nction f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f000(){retu" ascii
    $s8  = "nction f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"DIa\";})(),(function f000(){retu" ascii
    $s9  = "ction f000(){return \"Wh\";})(),(function f000(){return \"Ut\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s10 = "eturn \"Wh\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}