rule TTP_XOR_MULT_DOSStub_e760 {
  strings:
    $key_e760 = { b3 08 [2] c7 10 [2] 80 12 [2] c7 03 [2] 89 0f [2] 85 05 [2] 92 0e [2] 89 40 [2] b4 }

  condition:
    any of them
}