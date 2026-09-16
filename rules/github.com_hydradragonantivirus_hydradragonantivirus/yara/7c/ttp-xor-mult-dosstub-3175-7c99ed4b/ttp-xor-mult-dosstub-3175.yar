rule TTP_XOR_MULT_DOSStub_3175 {
  strings:
    $key_3175 = { 65 1d [2] 11 05 [2] 56 07 [2] 11 16 [2] 5f 1a [2] 53 10 [2] 44 1b [2] 5f 55 [2] 62 }

  condition:
    any of them
}