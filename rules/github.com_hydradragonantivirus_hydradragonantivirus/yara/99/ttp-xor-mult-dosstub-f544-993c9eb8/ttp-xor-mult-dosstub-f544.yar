rule TTP_XOR_MULT_DOSStub_f544 {
  strings:
    $key_f544 = { a1 2c [2] d5 34 [2] 92 36 [2] d5 27 [2] 9b 2b [2] 97 21 [2] 80 2a [2] 9b 64 [2] a6 }

  condition:
    any of them
}