rule TTP_XOR_MULT_DOSStub_f22c {
  strings:
    $key_f22c = { a6 44 [2] d2 5c [2] 95 5e [2] d2 4f [2] 9c 43 [2] 90 49 [2] 87 42 [2] 9c 0c [2] a1 }

  condition:
    any of them
}