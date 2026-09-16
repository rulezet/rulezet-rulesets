rule TTP_XOR_MULT_DOSStub_e4c1 {
  strings:
    $key_e4c1 = { b0 a9 [2] c4 b1 [2] 83 b3 [2] c4 a2 [2] 8a ae [2] 86 a4 [2] 91 af [2] 8a e1 [2] b7 }

  condition:
    any of them
}