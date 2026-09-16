rule TTP_XOR_MULT_DOSStub_e756 {
  strings:
    $key_e756 = { b3 3e [2] c7 26 [2] 80 24 [2] c7 35 [2] 89 39 [2] 85 33 [2] 92 38 [2] 89 76 [2] b4 }

  condition:
    any of them
}