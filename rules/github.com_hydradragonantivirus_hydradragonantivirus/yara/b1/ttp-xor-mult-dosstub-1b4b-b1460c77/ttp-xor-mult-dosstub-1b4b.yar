rule TTP_XOR_MULT_DOSStub_1b4b {
  strings:
    $key_1b4b = { 4f 23 [2] 3b 3b [2] 7c 39 [2] 3b 28 [2] 75 24 [2] 79 2e [2] 6e 25 [2] 75 6b [2] 48 }

  condition:
    any of them
}