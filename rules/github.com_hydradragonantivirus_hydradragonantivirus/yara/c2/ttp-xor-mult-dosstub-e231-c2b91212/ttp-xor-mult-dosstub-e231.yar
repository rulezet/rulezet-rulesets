rule TTP_XOR_MULT_DOSStub_e231 {
  strings:
    $key_e231 = { b6 59 [2] c2 41 [2] 85 43 [2] c2 52 [2] 8c 5e [2] 80 54 [2] 97 5f [2] 8c 11 [2] b1 }

  condition:
    any of them
}