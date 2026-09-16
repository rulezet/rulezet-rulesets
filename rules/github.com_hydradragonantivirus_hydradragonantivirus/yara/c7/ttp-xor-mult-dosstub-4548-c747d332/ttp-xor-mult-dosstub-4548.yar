rule TTP_XOR_MULT_DOSStub_4548 {
  strings:
    $key_4548 = { 11 20 [2] 65 38 [2] 22 3a [2] 65 2b [2] 2b 27 [2] 27 2d [2] 30 26 [2] 2b 68 [2] 16 }

  condition:
    any of them
}