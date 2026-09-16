rule TTP_XOR_MULT_DOSStub_4c1b {
  strings:
    $key_4c1b = { 18 73 [2] 6c 6b [2] 2b 69 [2] 6c 78 [2] 22 74 [2] 2e 7e [2] 39 75 [2] 22 3b [2] 1f }

  condition:
    any of them
}