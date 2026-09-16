rule TTP_XOR_MULT_DOSStub_103e {
  strings:
    $key_103e = { 44 56 [2] 30 4e [2] 77 4c [2] 30 5d [2] 7e 51 [2] 72 5b [2] 65 50 [2] 7e 1e [2] 43 }

  condition:
    any of them
}