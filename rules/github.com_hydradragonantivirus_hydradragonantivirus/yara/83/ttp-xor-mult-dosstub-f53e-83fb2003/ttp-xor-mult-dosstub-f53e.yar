rule TTP_XOR_MULT_DOSStub_f53e {
  strings:
    $key_f53e = { a1 56 [2] d5 4e [2] 92 4c [2] d5 5d [2] 9b 51 [2] 97 5b [2] 80 50 [2] 9b 1e [2] a6 }

  condition:
    any of them
}