rule TTP_XOR_MULT_DOSStub_3ae1 {
  strings:
    $key_3ae1 = { 6e 89 [2] 1a 91 [2] 5d 93 [2] 1a 82 [2] 54 8e [2] 58 84 [2] 4f 8f [2] 54 c1 [2] 69 }

  condition:
    any of them
}