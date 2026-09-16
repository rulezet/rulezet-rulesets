rule TTP_XOR_MULT_DOSStub_e244 {
  strings:
    $key_e244 = { b6 2c [2] c2 34 [2] 85 36 [2] c2 27 [2] 8c 2b [2] 80 21 [2] 97 2a [2] 8c 64 [2] b1 }

  condition:
    any of them
}