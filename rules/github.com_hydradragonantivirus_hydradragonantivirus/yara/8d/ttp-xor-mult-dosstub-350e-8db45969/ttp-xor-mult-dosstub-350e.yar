rule TTP_XOR_MULT_DOSStub_350e {
  strings:
    $key_350e = { 61 66 [2] 15 7e [2] 52 7c [2] 15 6d [2] 5b 61 [2] 57 6b [2] 40 60 [2] 5b 2e [2] 66 }

  condition:
    any of them
}