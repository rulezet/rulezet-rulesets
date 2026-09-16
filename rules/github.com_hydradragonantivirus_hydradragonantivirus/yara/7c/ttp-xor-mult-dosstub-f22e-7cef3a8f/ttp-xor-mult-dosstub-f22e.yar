rule TTP_XOR_MULT_DOSStub_f22e {
  strings:
    $key_f22e = { a6 46 [2] d2 5e [2] 95 5c [2] d2 4d [2] 9c 41 [2] 90 4b [2] 87 40 [2] 9c 0e [2] a1 }

  condition:
    any of them
}