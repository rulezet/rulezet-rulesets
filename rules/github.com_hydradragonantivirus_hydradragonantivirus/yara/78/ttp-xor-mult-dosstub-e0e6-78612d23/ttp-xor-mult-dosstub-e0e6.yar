rule TTP_XOR_MULT_DOSStub_e0e6 {
  strings:
    $key_e0e6 = { b4 8e [2] c0 96 [2] 87 94 [2] c0 85 [2] 8e 89 [2] 82 83 [2] 95 88 [2] 8e c6 [2] b3 }

  condition:
    any of them
}