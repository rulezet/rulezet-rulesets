rule TTP_XOR_MULT_DOSStub_037e {
  strings:
    $key_037e = { 57 16 [2] 23 0e [2] 64 0c [2] 23 1d [2] 6d 11 [2] 61 1b [2] 76 10 [2] 6d 5e [2] 50 }

  condition:
    any of them
}