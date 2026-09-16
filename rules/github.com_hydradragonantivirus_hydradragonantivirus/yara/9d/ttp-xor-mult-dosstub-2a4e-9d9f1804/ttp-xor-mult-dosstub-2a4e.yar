rule TTP_XOR_MULT_DOSStub_2a4e {
  strings:
    $key_2a4e = { 7e 26 [2] 0a 3e [2] 4d 3c [2] 0a 2d [2] 44 21 [2] 48 2b [2] 5f 20 [2] 44 6e [2] 79 }

  condition:
    any of them
}