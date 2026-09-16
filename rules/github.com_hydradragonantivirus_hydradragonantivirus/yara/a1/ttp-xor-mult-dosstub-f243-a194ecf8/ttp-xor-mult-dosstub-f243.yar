rule TTP_XOR_MULT_DOSStub_f243 {
  strings:
    $key_f243 = { a6 2b [2] d2 33 [2] 95 31 [2] d2 20 [2] 9c 2c [2] 90 26 [2] 87 2d [2] 9c 63 [2] a1 }

  condition:
    any of them
}