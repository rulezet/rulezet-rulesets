rule TTP_XOR_MULT_DOSStub_f548 {
  strings:
    $key_f548 = { a1 20 [2] d5 38 [2] 92 3a [2] d5 2b [2] 9b 27 [2] 97 2d [2] 80 26 [2] 9b 68 [2] a6 }

  condition:
    any of them
}