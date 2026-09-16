rule TTP_XOR_MULT_DOSStub_e141 {
  strings:
    $key_e141 = { b5 29 [2] c1 31 [2] 86 33 [2] c1 22 [2] 8f 2e [2] 83 24 [2] 94 2f [2] 8f 61 [2] b2 }

  condition:
    any of them
}