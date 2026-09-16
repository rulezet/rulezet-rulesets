rule TTP_XOR_MULT_DOSStub_701b {
  strings:
    $key_701b = { 24 73 [2] 50 6b [2] 17 69 [2] 50 78 [2] 1e 74 [2] 12 7e [2] 05 75 [2] 1e 3b [2] 23 }

  condition:
    any of them
}