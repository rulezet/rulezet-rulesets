rule TTP_XOR_MULT_DOSStub_0b4b {
  strings:
    $key_0b4b = { 5f 23 [2] 2b 3b [2] 6c 39 [2] 2b 28 [2] 65 24 [2] 69 2e [2] 7e 25 [2] 65 6b [2] 58 }

  condition:
    any of them
}