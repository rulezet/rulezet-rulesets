rule TTP_XOR_MULT_DOSStub_1b0e {
  strings:
    $key_1b0e = { 4f 66 [2] 3b 7e [2] 7c 7c [2] 3b 6d [2] 75 61 [2] 79 6b [2] 6e 60 [2] 75 2e [2] 48 }

  condition:
    any of them
}