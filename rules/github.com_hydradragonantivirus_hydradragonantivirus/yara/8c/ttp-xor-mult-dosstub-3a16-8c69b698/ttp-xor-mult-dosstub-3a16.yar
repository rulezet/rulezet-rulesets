rule TTP_XOR_MULT_DOSStub_3a16 {
  strings:
    $key_3a16 = { 6e 7e [2] 1a 66 [2] 5d 64 [2] 1a 75 [2] 54 79 [2] 58 73 [2] 4f 78 [2] 54 36 [2] 69 }

  condition:
    any of them
}