rule TTP_XOR_MULT_DOSStub_776e {
  strings:
    $key_776e = { 23 06 [2] 57 1e [2] 10 1c [2] 57 0d [2] 19 01 [2] 15 0b [2] 02 00 [2] 19 4e [2] 24 }

  condition:
    any of them
}