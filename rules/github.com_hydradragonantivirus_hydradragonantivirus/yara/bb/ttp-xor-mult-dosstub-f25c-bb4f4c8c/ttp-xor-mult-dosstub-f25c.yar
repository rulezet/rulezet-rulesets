rule TTP_XOR_MULT_DOSStub_f25c {
  strings:
    $key_f25c = { a6 34 [2] d2 2c [2] 95 2e [2] d2 3f [2] 9c 33 [2] 90 39 [2] 87 32 [2] 9c 7c [2] a1 }

  condition:
    any of them
}