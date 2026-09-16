rule TTP_XOR_MULT_DOSStub_4d1e {
  strings:
    $key_4d1e = { 19 76 [2] 6d 6e [2] 2a 6c [2] 6d 7d [2] 23 71 [2] 2f 7b [2] 38 70 [2] 23 3e [2] 1e }

  condition:
    any of them
}