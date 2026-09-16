rule TTP_XOR_MULT_DOSStub_e350 {
  strings:
    $key_e350 = { b7 38 [2] c3 20 [2] 84 22 [2] c3 33 [2] 8d 3f [2] 81 35 [2] 96 3e [2] 8d 70 [2] b0 }

  condition:
    any of them
}