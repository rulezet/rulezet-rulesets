rule TTP_XOR_MULT_DOSStub_1e2e {
  strings:
    $key_1e2e = { 4a 46 [2] 3e 5e [2] 79 5c [2] 3e 4d [2] 70 41 [2] 7c 4b [2] 6b 40 [2] 70 0e [2] 4d }

  condition:
    any of them
}