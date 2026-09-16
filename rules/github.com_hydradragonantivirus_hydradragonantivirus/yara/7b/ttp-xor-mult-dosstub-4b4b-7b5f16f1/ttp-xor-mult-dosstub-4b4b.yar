rule TTP_XOR_MULT_DOSStub_4b4b {
  strings:
    $key_4b4b = { 1f 23 [2] 6b 3b [2] 2c 39 [2] 6b 28 [2] 25 24 [2] 29 2e [2] 3e 25 [2] 25 6b [2] 18 }

  condition:
    any of them
}