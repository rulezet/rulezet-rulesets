rule TTP_XOR_MULT_DOSStub_f42e {
  strings:
    $key_f42e = { a0 46 [2] d4 5e [2] 93 5c [2] d4 4d [2] 9a 41 [2] 96 4b [2] 81 40 [2] 9a 0e [2] a7 }

  condition:
    any of them
}