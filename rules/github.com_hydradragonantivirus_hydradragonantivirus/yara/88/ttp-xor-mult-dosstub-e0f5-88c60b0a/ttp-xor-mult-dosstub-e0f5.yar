rule TTP_XOR_MULT_DOSStub_e0f5 {
  strings:
    $key_e0f5 = { b4 9d [2] c0 85 [2] 87 87 [2] c0 96 [2] 8e 9a [2] 82 90 [2] 95 9b [2] 8e d5 [2] b3 }

  condition:
    any of them
}