rule TTP_XOR_MULT_DOSStub_e241 {
  strings:
    $key_e241 = { b6 29 [2] c2 31 [2] 85 33 [2] c2 22 [2] 8c 2e [2] 80 24 [2] 97 2f [2] 8c 61 [2] b1 }

  condition:
    any of them
}