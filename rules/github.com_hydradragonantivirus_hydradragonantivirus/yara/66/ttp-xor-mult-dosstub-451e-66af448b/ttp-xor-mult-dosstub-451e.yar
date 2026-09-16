rule TTP_XOR_MULT_DOSStub_451e {
  strings:
    $key_451e = { 11 76 [2] 65 6e [2] 22 6c [2] 65 7d [2] 2b 71 [2] 27 7b [2] 30 70 [2] 2b 3e [2] 16 }

  condition:
    any of them
}