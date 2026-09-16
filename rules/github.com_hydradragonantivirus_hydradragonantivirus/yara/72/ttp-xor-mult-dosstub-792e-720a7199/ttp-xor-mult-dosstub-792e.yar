rule TTP_XOR_MULT_DOSStub_792e {
  strings:
    $key_792e = { 2d 46 [2] 59 5e [2] 1e 5c [2] 59 4d [2] 17 41 [2] 1b 4b [2] 0c 40 [2] 17 0e [2] 2a }

  condition:
    any of them
}