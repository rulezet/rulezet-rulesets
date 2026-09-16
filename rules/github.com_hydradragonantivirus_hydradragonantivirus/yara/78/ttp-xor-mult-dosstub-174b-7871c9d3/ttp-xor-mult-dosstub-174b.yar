rule TTP_XOR_MULT_DOSStub_174b {
  strings:
    $key_174b = { 43 23 [2] 37 3b [2] 70 39 [2] 37 28 [2] 79 24 [2] 75 2e [2] 62 25 [2] 79 6b [2] 44 }

  condition:
    any of them
}