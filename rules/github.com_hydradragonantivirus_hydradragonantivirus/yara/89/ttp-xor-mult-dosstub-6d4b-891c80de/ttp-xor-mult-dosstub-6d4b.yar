rule TTP_XOR_MULT_DOSStub_6d4b {
  strings:
    $key_6d4b = { 39 23 [2] 4d 3b [2] 0a 39 [2] 4d 28 [2] 03 24 [2] 0f 2e [2] 18 25 [2] 03 6b [2] 3e }

  condition:
    any of them
}