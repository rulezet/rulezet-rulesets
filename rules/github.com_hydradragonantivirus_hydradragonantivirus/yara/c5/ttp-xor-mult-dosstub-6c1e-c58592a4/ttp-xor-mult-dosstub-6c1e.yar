rule TTP_XOR_MULT_DOSStub_6c1e {
  strings:
    $key_6c1e = { 38 76 [2] 4c 6e [2] 0b 6c [2] 4c 7d [2] 02 71 [2] 0e 7b [2] 19 70 [2] 02 3e [2] 3f }

  condition:
    any of them
}