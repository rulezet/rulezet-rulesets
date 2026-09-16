rule TTP_XOR_MULT_DOSStub_f542 {
  strings:
    $key_f542 = { a1 2a [2] d5 32 [2] 92 30 [2] d5 21 [2] 9b 2d [2] 97 27 [2] 80 2c [2] 9b 62 [2] a6 }

  condition:
    any of them
}