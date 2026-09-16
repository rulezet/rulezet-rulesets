rule TTP_XOR_MULT_DOSStub_4c1e {
  strings:
    $key_4c1e = { 18 76 [2] 6c 6e [2] 2b 6c [2] 6c 7d [2] 22 71 [2] 2e 7b [2] 39 70 [2] 22 3e [2] 1f }

  condition:
    any of them
}