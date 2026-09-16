rule TTP_XOR_MULT_DOSStub_3a15 {
  strings:
    $key_3a15 = { 6e 7d [2] 1a 65 [2] 5d 67 [2] 1a 76 [2] 54 7a [2] 58 70 [2] 4f 7b [2] 54 35 [2] 69 }

  condition:
    any of them
}