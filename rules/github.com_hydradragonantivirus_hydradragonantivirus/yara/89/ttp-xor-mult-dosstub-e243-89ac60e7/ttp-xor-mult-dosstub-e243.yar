rule TTP_XOR_MULT_DOSStub_e243 {
  strings:
    $key_e243 = { b6 2b [2] c2 33 [2] 85 31 [2] c2 20 [2] 8c 2c [2] 80 26 [2] 97 2d [2] 8c 63 [2] b1 }

  condition:
    any of them
}