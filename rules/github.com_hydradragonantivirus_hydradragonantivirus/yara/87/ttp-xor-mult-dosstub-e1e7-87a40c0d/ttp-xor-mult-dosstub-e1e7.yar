rule TTP_XOR_MULT_DOSStub_e1e7 {
  strings:
    $key_e1e7 = { b5 8f [2] c1 97 [2] 86 95 [2] c1 84 [2] 8f 88 [2] 83 82 [2] 94 89 [2] 8f c7 [2] b2 }

  condition:
    any of them
}