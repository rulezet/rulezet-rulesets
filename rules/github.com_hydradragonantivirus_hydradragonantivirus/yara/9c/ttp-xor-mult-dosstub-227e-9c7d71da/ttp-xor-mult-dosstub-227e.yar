rule TTP_XOR_MULT_DOSStub_227e {
  strings:
    $key_227e = { 76 16 [2] 02 0e [2] 45 0c [2] 02 1d [2] 4c 11 [2] 40 1b [2] 57 10 [2] 4c 5e [2] 71 }

  condition:
    any of them
}