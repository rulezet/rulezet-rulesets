rule TTP_XOR_MULT_DOSStub_2a4b {
  strings:
    $key_2a4b = { 7e 23 [2] 0a 3b [2] 4d 39 [2] 0a 28 [2] 44 24 [2] 48 2e [2] 5f 25 [2] 44 6b [2] 79 }

  condition:
    any of them
}