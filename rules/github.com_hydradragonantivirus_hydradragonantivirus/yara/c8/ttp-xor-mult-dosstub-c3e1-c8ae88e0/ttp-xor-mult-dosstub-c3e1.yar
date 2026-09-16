rule TTP_XOR_MULT_DOSStub_c3e1 {
  strings:
    $key_c3e1 = { 97 89 [2] e3 91 [2] a4 93 [2] e3 82 [2] ad 8e [2] a1 84 [2] b6 8f [2] ad c1 [2] 90 }

  condition:
    any of them
}