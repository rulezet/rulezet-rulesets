rule TTP_XOR_MULT_DOSStub_e447 {
  strings:
    $key_e447 = { b0 2f [2] c4 37 [2] 83 35 [2] c4 24 [2] 8a 28 [2] 86 22 [2] 91 29 [2] 8a 67 [2] b7 }

  condition:
    any of them
}