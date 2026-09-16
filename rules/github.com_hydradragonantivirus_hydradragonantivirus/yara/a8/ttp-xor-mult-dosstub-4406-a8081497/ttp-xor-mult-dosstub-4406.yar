rule TTP_XOR_MULT_DOSStub_4406 {
  strings:
    $key_4406 = { 10 6e [2] 64 76 [2] 23 74 [2] 64 65 [2] 2a 69 [2] 26 63 [2] 31 68 [2] 2a 26 [2] 17 }

  condition:
    any of them
}