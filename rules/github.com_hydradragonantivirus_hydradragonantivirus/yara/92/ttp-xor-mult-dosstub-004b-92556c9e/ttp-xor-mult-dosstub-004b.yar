rule TTP_XOR_MULT_DOSStub_004b {
  strings:
    $key_004b = { 54 23 [2] 20 3b [2] 67 39 [2] 20 28 [2] 6e 24 [2] 62 2e [2] 75 25 [2] 6e 6b [2] 53 }

  condition:
    any of them
}