rule TTP_XOR_MULT_DOSStub_4d2e {
  strings:
    $key_4d2e = { 19 46 [2] 6d 5e [2] 2a 5c [2] 6d 4d [2] 23 41 [2] 2f 4b [2] 38 40 [2] 23 0e [2] 1e }

  condition:
    any of them
}