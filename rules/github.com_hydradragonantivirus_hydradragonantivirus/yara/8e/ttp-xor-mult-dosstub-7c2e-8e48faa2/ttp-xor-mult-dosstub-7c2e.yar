rule TTP_XOR_MULT_DOSStub_7c2e {
  strings:
    $key_7c2e = { 28 46 [2] 5c 5e [2] 1b 5c [2] 5c 4d [2] 12 41 [2] 1e 4b [2] 09 40 [2] 12 0e [2] 2f }

  condition:
    any of them
}