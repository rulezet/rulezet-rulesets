rule TTP_XOR_MULT_DOSStub_0fe1 {
  strings:
    $key_0fe1 = { 5b 89 [2] 2f 91 [2] 68 93 [2] 2f 82 [2] 61 8e [2] 6d 84 [2] 7a 8f [2] 61 c1 [2] 5c }

  condition:
    any of them
}