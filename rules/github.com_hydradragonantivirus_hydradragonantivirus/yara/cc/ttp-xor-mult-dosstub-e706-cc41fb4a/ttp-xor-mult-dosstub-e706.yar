rule TTP_XOR_MULT_DOSStub_e706 {
  strings:
    $key_e706 = { b3 6e [2] c7 76 [2] 80 74 [2] c7 65 [2] 89 69 [2] 85 63 [2] 92 68 [2] 89 26 [2] b4 }

  condition:
    any of them
}