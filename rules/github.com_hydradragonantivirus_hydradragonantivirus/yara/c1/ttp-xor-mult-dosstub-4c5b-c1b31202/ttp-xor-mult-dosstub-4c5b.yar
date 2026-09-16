rule TTP_XOR_MULT_DOSStub_4c5b {
  strings:
    $key_4c5b = { 18 33 [2] 6c 2b [2] 2b 29 [2] 6c 38 [2] 22 34 [2] 2e 3e [2] 39 35 [2] 22 7b [2] 1f }

  condition:
    any of them
}