rule TTP_XOR_MULT_DOSStub_3af1 {
  strings:
    $key_3af1 = { 6e 99 [2] 1a 81 [2] 5d 83 [2] 1a 92 [2] 54 9e [2] 58 94 [2] 4f 9f [2] 54 d1 [2] 69 }

  condition:
    any of them
}