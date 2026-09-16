rule TTP_XOR_MULT_DOSStub_f750 {
  strings:
    $key_f750 = { a3 38 [2] d7 20 [2] 90 22 [2] d7 33 [2] 99 3f [2] 95 35 [2] 82 3e [2] 99 70 [2] a4 }

  condition:
    any of them
}