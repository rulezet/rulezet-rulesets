rule TTP_XOR_MULT_DOSStub_381e {
  strings:
    $key_381e = { 6c 76 [2] 18 6e [2] 5f 6c [2] 18 7d [2] 56 71 [2] 5a 7b [2] 4d 70 [2] 56 3e [2] 6b }

  condition:
    any of them
}