rule TTP_XOR_MULT_DOSStub_640e {
  strings:
    $key_640e = { 30 66 [2] 44 7e [2] 03 7c [2] 44 6d [2] 0a 61 [2] 06 6b [2] 11 60 [2] 0a 2e [2] 37 }

  condition:
    any of them
}