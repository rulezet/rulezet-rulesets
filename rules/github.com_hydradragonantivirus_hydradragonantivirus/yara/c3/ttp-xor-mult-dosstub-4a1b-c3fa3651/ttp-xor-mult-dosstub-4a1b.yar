rule TTP_XOR_MULT_DOSStub_4a1b {
  strings:
    $key_4a1b = { 1e 73 [2] 6a 6b [2] 2d 69 [2] 6a 78 [2] 24 74 [2] 28 7e [2] 3f 75 [2] 24 3b [2] 19 }

  condition:
    any of them
}