rule TTP_XOR_MULT_DOSStub_e1f7 {
  strings:
    $key_e1f7 = { b5 9f [2] c1 87 [2] 86 85 [2] c1 94 [2] 8f 98 [2] 83 92 [2] 94 99 [2] 8f d7 [2] b2 }

  condition:
    any of them
}