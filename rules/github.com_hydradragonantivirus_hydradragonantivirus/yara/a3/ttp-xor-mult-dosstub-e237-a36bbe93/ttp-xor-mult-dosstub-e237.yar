rule TTP_XOR_MULT_DOSStub_e237 {
  strings:
    $key_e237 = { b6 5f [2] c2 47 [2] 85 45 [2] c2 54 [2] 8c 58 [2] 80 52 [2] 97 59 [2] 8c 17 [2] b1 }

  condition:
    any of them
}