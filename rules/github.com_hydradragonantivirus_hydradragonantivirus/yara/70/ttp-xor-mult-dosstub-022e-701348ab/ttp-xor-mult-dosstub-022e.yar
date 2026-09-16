rule TTP_XOR_MULT_DOSStub_022e {
  strings:
    $key_022e = { 56 46 [2] 22 5e [2] 65 5c [2] 22 4d [2] 6c 41 [2] 60 4b [2] 77 40 [2] 6c 0e [2] 51 }

  condition:
    any of them
}