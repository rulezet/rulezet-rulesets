rule TTP_XOR_MULT_DOSStub_e4f7 {
  strings:
    $key_e4f7 = { b0 9f [2] c4 87 [2] 83 85 [2] c4 94 [2] 8a 98 [2] 86 92 [2] 91 99 [2] 8a d7 [2] b7 }

  condition:
    any of them
}