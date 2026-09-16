rule TTP_XOR_MULT_DOSStub_4ae1 {
  strings:
    $key_4ae1 = { 1e 89 [2] 6a 91 [2] 2d 93 [2] 6a 82 [2] 24 8e [2] 28 84 [2] 3f 8f [2] 24 c1 [2] 19 }

  condition:
    any of them
}