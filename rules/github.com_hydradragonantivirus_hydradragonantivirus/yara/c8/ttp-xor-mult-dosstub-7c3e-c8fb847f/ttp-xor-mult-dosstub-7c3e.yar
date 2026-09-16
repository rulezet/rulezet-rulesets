rule TTP_XOR_MULT_DOSStub_7c3e {
  strings:
    $key_7c3e = { 28 56 [2] 5c 4e [2] 1b 4c [2] 5c 5d [2] 12 51 [2] 1e 5b [2] 09 50 [2] 12 1e [2] 2f }

  condition:
    any of them
}