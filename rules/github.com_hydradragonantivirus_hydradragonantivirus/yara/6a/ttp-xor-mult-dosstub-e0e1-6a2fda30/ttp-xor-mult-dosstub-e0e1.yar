rule TTP_XOR_MULT_DOSStub_e0e1 {
  strings:
    $key_e0e1 = { b4 89 [2] c0 91 [2] 87 93 [2] c0 82 [2] 8e 8e [2] 82 84 [2] 95 8f [2] 8e c1 [2] b3 }

  condition:
    any of them
}