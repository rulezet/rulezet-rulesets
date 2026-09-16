rule TTP_XOR_MULT_DOSStub_324b {
  strings:
    $key_324b = { 66 23 [2] 12 3b [2] 55 39 [2] 12 28 [2] 5c 24 [2] 50 2e [2] 47 25 [2] 5c 6b [2] 61 }

  condition:
    any of them
}