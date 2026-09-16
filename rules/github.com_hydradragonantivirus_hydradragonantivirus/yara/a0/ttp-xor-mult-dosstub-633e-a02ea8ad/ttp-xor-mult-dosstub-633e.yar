rule TTP_XOR_MULT_DOSStub_633e {
  strings:
    $key_633e = { 37 56 [2] 43 4e [2] 04 4c [2] 43 5d [2] 0d 51 [2] 01 5b [2] 16 50 [2] 0d 1e [2] 30 }

  condition:
    any of them
}