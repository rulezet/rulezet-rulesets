rule TTP_XOR_MULT_DOSStub_1a0e {
  strings:
    $key_1a0e = { 4e 66 [2] 3a 7e [2] 7d 7c [2] 3a 6d [2] 74 61 [2] 78 6b [2] 6f 60 [2] 74 2e [2] 49 }

  condition:
    any of them
}