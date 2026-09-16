rule TTP_XOR_MULT_DOSStub_3170 {
  strings:
    $key_3170 = { 65 18 [2] 11 00 [2] 56 02 [2] 11 13 [2] 5f 1f [2] 53 15 [2] 44 1e [2] 5f 50 [2] 62 }

  condition:
    any of them
}