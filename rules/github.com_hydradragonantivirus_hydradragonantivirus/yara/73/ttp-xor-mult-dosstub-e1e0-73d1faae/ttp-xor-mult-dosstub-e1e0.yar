rule TTP_XOR_MULT_DOSStub_e1e0 {
  strings:
    $key_e1e0 = { b5 88 [2] c1 90 [2] 86 92 [2] c1 83 [2] 8f 8f [2] 83 85 [2] 94 8e [2] 8f c0 [2] b2 }

  condition:
    any of them
}