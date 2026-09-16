rule TTP_XOR_MULT_DOSStub_e1e6 {
  strings:
    $key_e1e6 = { b5 8e [2] c1 96 [2] 86 94 [2] c1 85 [2] 8f 89 [2] 83 83 [2] 94 88 [2] 8f c6 [2] b2 }

  condition:
    any of them
}