rule TTP_XOR_MULT_DOSStub_4d4e {
  strings:
    $key_4d4e = { 19 26 [2] 6d 3e [2] 2a 3c [2] 6d 2d [2] 23 21 [2] 2f 2b [2] 38 20 [2] 23 6e [2] 1e }

  condition:
    any of them
}