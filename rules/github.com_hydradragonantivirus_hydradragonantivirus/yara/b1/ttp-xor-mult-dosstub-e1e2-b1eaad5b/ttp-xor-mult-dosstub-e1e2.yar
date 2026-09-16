rule TTP_XOR_MULT_DOSStub_e1e2 {
  strings:
    $key_e1e2 = { b5 8a [2] c1 92 [2] 86 90 [2] c1 81 [2] 8f 8d [2] 83 87 [2] 94 8c [2] 8f c2 [2] b2 }

  condition:
    any of them
}