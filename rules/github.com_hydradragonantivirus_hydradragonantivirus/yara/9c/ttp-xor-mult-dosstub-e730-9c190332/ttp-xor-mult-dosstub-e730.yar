rule TTP_XOR_MULT_DOSStub_e730 {
  strings:
    $key_e730 = { b3 58 [2] c7 40 [2] 80 42 [2] c7 53 [2] 89 5f [2] 85 55 [2] 92 5e [2] 89 10 [2] b4 }

  condition:
    any of them
}