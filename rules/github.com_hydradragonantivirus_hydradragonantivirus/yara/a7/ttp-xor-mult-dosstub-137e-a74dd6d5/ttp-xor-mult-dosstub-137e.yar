rule TTP_XOR_MULT_DOSStub_137e {
  strings:
    $key_137e = { 47 16 [2] 33 0e [2] 74 0c [2] 33 1d [2] 7d 11 [2] 71 1b [2] 66 10 [2] 7d 5e [2] 40 }

  condition:
    any of them
}