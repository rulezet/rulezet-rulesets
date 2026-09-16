rule TTP_XOR_MULT_DOSStub_3a37 {
  strings:
    $key_3a37 = { 6e 5f [2] 1a 47 [2] 5d 45 [2] 1a 54 [2] 54 58 [2] 58 52 [2] 4f 59 [2] 54 17 [2] 69 }

  condition:
    any of them
}