rule TTP_XOR_MULT_DOSStub_673e {
  strings:
    $key_673e = { 33 56 [2] 47 4e [2] 00 4c [2] 47 5d [2] 09 51 [2] 05 5b [2] 12 50 [2] 09 1e [2] 34 }

  condition:
    any of them
}