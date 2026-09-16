rule TTP_XOR_MULT_DOSStub_e750 {
  strings:
    $key_e750 = { b3 38 [2] c7 20 [2] 80 22 [2] c7 33 [2] 89 3f [2] 85 35 [2] 92 3e [2] 89 70 [2] b4 }

  condition:
    any of them
}