rule TTP_XOR_MULT_DOSStub_cd68 {
  strings:
    $key_cd68 = { 99 00 [2] ed 18 [2] aa 1a [2] ed 0b [2] a3 07 [2] af 0d [2] b8 06 [2] a3 48 [2] 9e }

  condition:
    any of them
}