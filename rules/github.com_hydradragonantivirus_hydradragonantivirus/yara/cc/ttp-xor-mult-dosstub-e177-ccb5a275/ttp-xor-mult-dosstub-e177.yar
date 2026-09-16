rule TTP_XOR_MULT_DOSStub_e177 {
  strings:
    $key_e177 = { b5 1f [2] c1 07 [2] 86 05 [2] c1 14 [2] 8f 18 [2] 83 12 [2] 94 19 [2] 8f 57 [2] b2 }

  condition:
    any of them
}