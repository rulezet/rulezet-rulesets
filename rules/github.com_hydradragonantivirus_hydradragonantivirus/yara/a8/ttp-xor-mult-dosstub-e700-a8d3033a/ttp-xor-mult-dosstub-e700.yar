rule TTP_XOR_MULT_DOSStub_e700 {
  strings:
    $key_e700 = { b3 68 [2] c7 70 [2] 80 72 [2] c7 63 [2] 89 6f [2] 85 65 [2] 92 6e [2] 89 20 [2] b4 }

  condition:
    any of them
}