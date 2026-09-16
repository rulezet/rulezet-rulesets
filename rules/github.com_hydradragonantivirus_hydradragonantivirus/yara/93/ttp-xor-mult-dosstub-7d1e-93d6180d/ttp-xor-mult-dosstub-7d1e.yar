rule TTP_XOR_MULT_DOSStub_7d1e {
  strings:
    $key_7d1e = { 29 76 [2] 5d 6e [2] 1a 6c [2] 5d 7d [2] 13 71 [2] 1f 7b [2] 08 70 [2] 13 3e [2] 2e }

  condition:
    any of them
}