rule TTP_XOR_MULT_DOSStub_f430 {
  strings:
    $key_f430 = { a0 58 [2] d4 40 [2] 93 42 [2] d4 53 [2] 9a 5f [2] 96 55 [2] 81 5e [2] 9a 10 [2] a7 }

  condition:
    any of them
}