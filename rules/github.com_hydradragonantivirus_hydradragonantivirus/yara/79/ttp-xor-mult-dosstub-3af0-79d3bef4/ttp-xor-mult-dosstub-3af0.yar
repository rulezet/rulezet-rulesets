rule TTP_XOR_MULT_DOSStub_3af0 {
  strings:
    $key_3af0 = { 6e 98 [2] 1a 80 [2] 5d 82 [2] 1a 93 [2] 54 9f [2] 58 95 [2] 4f 9e [2] 54 d0 [2] 69 }

  condition:
    any of them
}