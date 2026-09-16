rule TTP_XOR_MULT_DOSStub_4a2e {
  strings:
    $key_4a2e = { 1e 46 [2] 6a 5e [2] 2d 5c [2] 6a 4d [2] 24 41 [2] 28 4b [2] 3f 40 [2] 24 0e [2] 19 }

  condition:
    any of them
}