rule TTP_XOR_MULT_DOSStub_600e {
  strings:
    $key_600e = { 34 66 [2] 40 7e [2] 07 7c [2] 40 6d [2] 0e 61 [2] 02 6b [2] 15 60 [2] 0e 2e [2] 33 }

  condition:
    any of them
}