rule TTP_XOR_MULT_DOSStub_2d4b {
  strings:
    $key_2d4b = { 79 23 [2] 0d 3b [2] 4a 39 [2] 0d 28 [2] 43 24 [2] 4f 2e [2] 58 25 [2] 43 6b [2] 7e }

  condition:
    any of them
}