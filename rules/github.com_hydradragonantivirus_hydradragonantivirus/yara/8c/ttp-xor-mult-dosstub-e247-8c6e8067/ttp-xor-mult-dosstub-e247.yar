rule TTP_XOR_MULT_DOSStub_e247 {
  strings:
    $key_e247 = { b6 2f [2] c2 37 [2] 85 35 [2] c2 24 [2] 8c 28 [2] 80 22 [2] 97 29 [2] 8c 67 [2] b1 }

  condition:
    any of them
}