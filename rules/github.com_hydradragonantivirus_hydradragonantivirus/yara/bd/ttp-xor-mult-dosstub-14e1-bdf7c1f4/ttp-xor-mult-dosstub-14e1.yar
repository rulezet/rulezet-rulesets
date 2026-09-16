rule TTP_XOR_MULT_DOSStub_14e1 {
  strings:
    $key_14e1 = { 40 89 [2] 34 91 [2] 73 93 [2] 34 82 [2] 7a 8e [2] 76 84 [2] 61 8f [2] 7a c1 [2] 47 }

  condition:
    any of them
}