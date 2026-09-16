rule TTP_XOR_MULT_DOSStub_e4f1 {
  strings:
    $key_e4f1 = { b0 99 [2] c4 81 [2] 83 83 [2] c4 92 [2] 8a 9e [2] 86 94 [2] 91 9f [2] 8a d1 [2] b7 }

  condition:
    any of them
}