rule TTP_XOR_MULT_DOSStub_4c3e {
  strings:
    $key_4c3e = { 18 56 [2] 6c 4e [2] 2b 4c [2] 6c 5d [2] 22 51 [2] 2e 5b [2] 39 50 [2] 22 1e [2] 1f }

  condition:
    any of them
}