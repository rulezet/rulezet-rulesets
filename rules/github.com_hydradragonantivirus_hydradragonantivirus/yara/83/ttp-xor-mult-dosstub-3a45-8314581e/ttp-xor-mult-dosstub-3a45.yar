rule TTP_XOR_MULT_DOSStub_3a45 {
  strings:
    $key_3a45 = { 6e 2d [2] 1a 35 [2] 5d 37 [2] 1a 26 [2] 54 2a [2] 58 20 [2] 4f 2b [2] 54 65 [2] 69 }

  condition:
    any of them
}