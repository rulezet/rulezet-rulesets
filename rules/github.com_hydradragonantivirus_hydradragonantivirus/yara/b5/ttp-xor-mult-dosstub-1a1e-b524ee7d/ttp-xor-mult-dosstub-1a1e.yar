rule TTP_XOR_MULT_DOSStub_1a1e {
  strings:
    $key_1a1e = { 4e 76 [2] 3a 6e [2] 7d 6c [2] 3a 7d [2] 74 71 [2] 78 7b [2] 6f 70 [2] 74 3e [2] 49 }

  condition:
    any of them
}