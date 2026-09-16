rule TTP_XOR_MULT_DOSStub_733e {
  strings:
    $key_733e = { 27 56 [2] 53 4e [2] 14 4c [2] 53 5d [2] 1d 51 [2] 11 5b [2] 06 50 [2] 1d 1e [2] 20 }

  condition:
    any of them
}