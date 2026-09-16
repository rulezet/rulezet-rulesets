rule TTP_XOR_MULT_DOSStub_e4b7 {
  strings:
    $key_e4b7 = { b0 df [2] c4 c7 [2] 83 c5 [2] c4 d4 [2] 8a d8 [2] 86 d2 [2] 91 d9 [2] 8a 97 [2] b7 }

  condition:
    any of them
}