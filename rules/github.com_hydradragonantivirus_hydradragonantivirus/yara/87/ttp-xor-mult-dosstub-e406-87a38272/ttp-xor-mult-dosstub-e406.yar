rule TTP_XOR_MULT_DOSStub_e406 {
  strings:
    $key_e406 = { b0 6e [2] c4 76 [2] 83 74 [2] c4 65 [2] 8a 69 [2] 86 63 [2] 91 68 [2] 8a 26 [2] b7 }

  condition:
    any of them
}