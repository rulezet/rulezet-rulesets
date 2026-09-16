rule TTP_XOR_MULT_DOSStub_1a2e {
  strings:
    $key_1a2e = { 4e 46 [2] 3a 5e [2] 7d 5c [2] 3a 4d [2] 74 41 [2] 78 4b [2] 6f 40 [2] 74 0e [2] 49 }

  condition:
    any of them
}