rule TTP_XOR_MULT_DOSStub_7a1e {
  strings:
    $key_7a1e = { 2e 76 [2] 5a 6e [2] 1d 6c [2] 5a 7d [2] 14 71 [2] 18 7b [2] 0f 70 [2] 14 3e [2] 29 }

  condition:
    any of them
}