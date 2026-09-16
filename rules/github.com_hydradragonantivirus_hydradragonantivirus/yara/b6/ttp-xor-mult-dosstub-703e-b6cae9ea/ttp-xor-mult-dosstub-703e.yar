rule TTP_XOR_MULT_DOSStub_703e {
  strings:
    $key_703e = { 24 56 [2] 50 4e [2] 17 4c [2] 50 5d [2] 1e 51 [2] 12 5b [2] 05 50 [2] 1e 1e [2] 23 }

  condition:
    any of them
}