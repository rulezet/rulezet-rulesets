rule TTP_XOR_MULT_DOSStub_124b {
  strings:
    $key_124b = { 46 23 [2] 32 3b [2] 75 39 [2] 32 28 [2] 7c 24 [2] 70 2e [2] 67 25 [2] 7c 6b [2] 41 }

  condition:
    any of them
}