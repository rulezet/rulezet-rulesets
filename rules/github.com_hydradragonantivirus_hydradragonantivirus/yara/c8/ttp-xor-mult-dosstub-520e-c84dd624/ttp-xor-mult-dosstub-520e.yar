rule TTP_XOR_MULT_DOSStub_520e {
  strings:
    $key_520e = { 06 66 [2] 72 7e [2] 35 7c [2] 72 6d [2] 3c 61 [2] 30 6b [2] 27 60 [2] 3c 2e [2] 01 }

  condition:
    any of them
}