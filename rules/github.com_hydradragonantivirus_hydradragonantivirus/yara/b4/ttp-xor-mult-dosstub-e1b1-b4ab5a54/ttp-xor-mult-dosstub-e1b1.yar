rule TTP_XOR_MULT_DOSStub_e1b1 {
  strings:
    $key_e1b1 = { b5 d9 [2] c1 c1 [2] 86 c3 [2] c1 d2 [2] 8f de [2] 83 d4 [2] 94 df [2] 8f 91 [2] b2 }

  condition:
    any of them
}