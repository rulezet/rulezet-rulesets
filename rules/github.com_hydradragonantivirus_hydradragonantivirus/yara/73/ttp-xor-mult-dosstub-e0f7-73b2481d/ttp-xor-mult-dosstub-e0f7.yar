rule TTP_XOR_MULT_DOSStub_e0f7 {
  strings:
    $key_e0f7 = { b4 9f [2] c0 87 [2] 87 85 [2] c0 94 [2] 8e 98 [2] 82 92 [2] 95 99 [2] 8e d7 [2] b3 }

  condition:
    any of them
}