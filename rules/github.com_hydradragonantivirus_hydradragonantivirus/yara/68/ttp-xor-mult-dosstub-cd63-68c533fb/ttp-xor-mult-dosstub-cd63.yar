rule TTP_XOR_MULT_DOSStub_cd63 {
  strings:
    $key_cd63 = { 99 0b [2] ed 13 [2] aa 11 [2] ed 00 [2] a3 0c [2] af 06 [2] b8 0d [2] a3 43 [2] 9e }

  condition:
    any of them
}