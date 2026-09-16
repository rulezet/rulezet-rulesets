rule TTP_XOR_MULT_DOSStub_f23d {
  strings:
    $key_f23d = { a6 55 [2] d2 4d [2] 95 4f [2] d2 5e [2] 9c 52 [2] 90 58 [2] 87 53 [2] 9c 1d [2] a1 }

  condition:
    any of them
}