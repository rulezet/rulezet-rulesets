rule TTP_XOR_MULT_DOSStub_cd75 {
  strings:
    $key_cd75 = { 99 1d [2] ed 05 [2] aa 07 [2] ed 16 [2] a3 1a [2] af 10 [2] b8 1b [2] a3 55 [2] 9e }

  condition:
    any of them
}