rule TTP_XOR_MULT_DOSStub_2a0e {
  strings:
    $key_2a0e = { 7e 66 [2] 0a 7e [2] 4d 7c [2] 0a 6d [2] 44 61 [2] 48 6b [2] 5f 60 [2] 44 2e [2] 79 }

  condition:
    any of them
}