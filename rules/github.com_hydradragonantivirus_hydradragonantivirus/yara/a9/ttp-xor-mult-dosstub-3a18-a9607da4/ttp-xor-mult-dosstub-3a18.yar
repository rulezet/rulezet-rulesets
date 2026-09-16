rule TTP_XOR_MULT_DOSStub_3a18 {
  strings:
    $key_3a18 = { 6e 70 [2] 1a 68 [2] 5d 6a [2] 1a 7b [2] 54 77 [2] 58 7d [2] 4f 76 [2] 54 38 [2] 69 }

  condition:
    any of them
}