rule TTP_XOR_MULT_DOSStub_e710 {
  strings:
    $key_e710 = { b3 78 [2] c7 60 [2] 80 62 [2] c7 73 [2] 89 7f [2] 85 75 [2] 92 7e [2] 89 30 [2] b4 }

  condition:
    any of them
}