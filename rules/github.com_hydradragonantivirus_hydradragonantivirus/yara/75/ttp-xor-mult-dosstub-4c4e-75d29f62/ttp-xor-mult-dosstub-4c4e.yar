rule TTP_XOR_MULT_DOSStub_4c4e {
  strings:
    $key_4c4e = { 18 26 [2] 6c 3e [2] 2b 3c [2] 6c 2d [2] 22 21 [2] 2e 2b [2] 39 20 [2] 22 6e [2] 1f }

  condition:
    any of them
}