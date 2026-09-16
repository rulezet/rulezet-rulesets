rule TTP_XOR_MULT_DOSStub_3ae6 {
  strings:
    $key_3ae6 = { 6e 8e [2] 1a 96 [2] 5d 94 [2] 1a 85 [2] 54 89 [2] 58 83 [2] 4f 88 [2] 54 c6 [2] 69 }

  condition:
    any of them
}