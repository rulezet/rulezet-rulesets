rule TTP_XOR_MULT_DOSStub_033e {
  strings:
    $key_033e = { 57 56 [2] 23 4e [2] 64 4c [2] 23 5d [2] 6d 51 [2] 61 5b [2] 76 50 [2] 6d 1e [2] 50 }

  condition:
    any of them
}