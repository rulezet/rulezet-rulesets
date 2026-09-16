rule TTP_XOR_MULT_DOSStub_364b {
  strings:
    $key_364b = { 62 23 [2] 16 3b [2] 51 39 [2] 16 28 [2] 58 24 [2] 54 2e [2] 43 25 [2] 58 6b [2] 65 }

  condition:
    any of them
}