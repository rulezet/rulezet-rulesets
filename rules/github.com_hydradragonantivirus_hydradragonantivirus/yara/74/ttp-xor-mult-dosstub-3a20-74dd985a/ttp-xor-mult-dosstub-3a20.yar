rule TTP_XOR_MULT_DOSStub_3a20 {
  strings:
    $key_3a20 = { 6e 48 [2] 1a 50 [2] 5d 52 [2] 1a 43 [2] 54 4f [2] 58 45 [2] 4f 4e [2] 54 00 [2] 69 }

  condition:
    any of them
}