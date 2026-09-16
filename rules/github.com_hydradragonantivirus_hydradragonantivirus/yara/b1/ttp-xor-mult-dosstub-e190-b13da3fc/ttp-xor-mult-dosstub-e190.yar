rule TTP_XOR_MULT_DOSStub_e190 {
  strings:
    $key_e190 = { b5 f8 [2] c1 e0 [2] 86 e2 [2] c1 f3 [2] 8f ff [2] 83 f5 [2] 94 fe [2] 8f b0 [2] b2 }

  condition:
    any of them
}