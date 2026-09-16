rule TTP_XOR_MULT_DOSStub_e550 {
  strings:
    $key_e550 = { b1 38 [2] c5 20 [2] 82 22 [2] c5 33 [2] 8b 3f [2] 87 35 [2] 90 3e [2] 8b 70 [2] b6 }

  condition:
    any of them
}