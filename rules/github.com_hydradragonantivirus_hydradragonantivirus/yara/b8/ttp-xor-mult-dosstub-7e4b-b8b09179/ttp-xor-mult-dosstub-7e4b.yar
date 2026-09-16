rule TTP_XOR_MULT_DOSStub_7e4b {
  strings:
    $key_7e4b = { 2a 23 [2] 5e 3b [2] 19 39 [2] 5e 28 [2] 10 24 [2] 1c 2e [2] 0b 25 [2] 10 6b [2] 2d }

  condition:
    any of them
}