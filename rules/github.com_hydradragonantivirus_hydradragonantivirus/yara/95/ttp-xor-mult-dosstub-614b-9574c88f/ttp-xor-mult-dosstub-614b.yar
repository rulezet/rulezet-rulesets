rule TTP_XOR_MULT_DOSStub_614b {
  strings:
    $key_614b = { 35 23 [2] 41 3b [2] 06 39 [2] 41 28 [2] 0f 24 [2] 03 2e [2] 14 25 [2] 0f 6b [2] 32 }

  condition:
    any of them
}