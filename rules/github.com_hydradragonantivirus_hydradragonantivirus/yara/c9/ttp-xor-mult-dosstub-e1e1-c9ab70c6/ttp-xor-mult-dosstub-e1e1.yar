rule TTP_XOR_MULT_DOSStub_e1e1 {
  strings:
    $key_e1e1 = { b5 89 [2] c1 91 [2] 86 93 [2] c1 82 [2] 8f 8e [2] 83 84 [2] 94 8f [2] 8f c1 [2] b2 }

  condition:
    any of them
}