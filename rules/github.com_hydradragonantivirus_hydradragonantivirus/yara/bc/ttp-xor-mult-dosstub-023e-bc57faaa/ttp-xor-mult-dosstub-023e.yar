rule TTP_XOR_MULT_DOSStub_023e {
  strings:
    $key_023e = { 56 56 [2] 22 4e [2] 65 4c [2] 22 5d [2] 6c 51 [2] 60 5b [2] 77 50 [2] 6c 1e [2] 51 }

  condition:
    any of them
}