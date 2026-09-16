rule TTP_XOR_MULT_DOSStub_4a5b {
  strings:
    $key_4a5b = { 1e 33 [2] 6a 2b [2] 2d 29 [2] 6a 38 [2] 24 34 [2] 28 3e [2] 3f 35 [2] 24 7b [2] 19 }

  condition:
    any of them
}