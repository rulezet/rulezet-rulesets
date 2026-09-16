rule TTP_XOR_MULT_DOSStub_3a50 {
  strings:
    $key_3a50 = { 6e 38 [2] 1a 20 [2] 5d 22 [2] 1a 33 [2] 54 3f [2] 58 35 [2] 4f 3e [2] 54 70 [2] 69 }

  condition:
    any of them
}