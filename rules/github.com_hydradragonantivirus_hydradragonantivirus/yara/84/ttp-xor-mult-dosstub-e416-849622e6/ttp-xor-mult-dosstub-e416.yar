rule TTP_XOR_MULT_DOSStub_e416 {
  strings:
    $key_e416 = { b0 7e [2] c4 66 [2] 83 64 [2] c4 75 [2] 8a 79 [2] 86 73 [2] 91 78 [2] 8a 36 [2] b7 }

  condition:
    any of them
}