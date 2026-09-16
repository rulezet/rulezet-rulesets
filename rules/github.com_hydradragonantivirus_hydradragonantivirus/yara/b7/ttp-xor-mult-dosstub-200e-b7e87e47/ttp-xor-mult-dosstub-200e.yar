rule TTP_XOR_MULT_DOSStub_200e {
  strings:
    $key_200e = { 74 66 [2] 00 7e [2] 47 7c [2] 00 6d [2] 4e 61 [2] 42 6b [2] 55 60 [2] 4e 2e [2] 73 }

  condition:
    any of them
}