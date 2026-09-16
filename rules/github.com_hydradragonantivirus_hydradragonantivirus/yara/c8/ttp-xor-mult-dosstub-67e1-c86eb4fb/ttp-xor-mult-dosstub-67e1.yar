rule TTP_XOR_MULT_DOSStub_67e1 {
  strings:
    $key_67e1 = { 33 89 [2] 47 91 [2] 00 93 [2] 47 82 [2] 09 8e [2] 05 84 [2] 12 8f [2] 09 c1 [2] 34 }

  condition:
    any of them
}