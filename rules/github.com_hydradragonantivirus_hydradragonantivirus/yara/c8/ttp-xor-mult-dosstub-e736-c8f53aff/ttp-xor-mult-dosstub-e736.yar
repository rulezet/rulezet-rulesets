rule TTP_XOR_MULT_DOSStub_e736 {
  strings:
    $key_e736 = { b3 5e [2] c7 46 [2] 80 44 [2] c7 55 [2] 89 59 [2] 85 53 [2] 92 58 [2] 89 16 [2] b4 }

  condition:
    any of them
}