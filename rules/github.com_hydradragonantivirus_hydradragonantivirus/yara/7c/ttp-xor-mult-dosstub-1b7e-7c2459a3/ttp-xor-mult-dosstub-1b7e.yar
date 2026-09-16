rule TTP_XOR_MULT_DOSStub_1b7e {
  strings:
    $key_1b7e = { 4f 16 [2] 3b 0e [2] 7c 0c [2] 3b 1d [2] 75 11 [2] 79 1b [2] 6e 10 [2] 75 5e [2] 48 }

  condition:
    any of them
}