rule TTP_XOR_MULT_DOSStub_e147 {
  strings:
    $key_e147 = { b5 2f [2] c1 37 [2] 86 35 [2] c1 24 [2] 8f 28 [2] 83 22 [2] 94 29 [2] 8f 67 [2] b2 }

  condition:
    any of them
}