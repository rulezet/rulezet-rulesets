rule TTP_XOR_MULT_DOSStub_e127 {
  strings:
    $key_e127 = { b5 4f [2] c1 57 [2] 86 55 [2] c1 44 [2] 8f 48 [2] 83 42 [2] 94 49 [2] 8f 07 [2] b2 }

  condition:
    any of them
}