rule TTP_XOR_MULT_DOSStub_f22d {
  strings:
    $key_f22d = { a6 45 [2] d2 5d [2] 95 5f [2] d2 4e [2] 9c 42 [2] 90 48 [2] 87 43 [2] 9c 0d [2] a1 }

  condition:
    any of them
}