rule TTP_XOR_MULT_DOSStub_164b {
  strings:
    $key_164b = { 42 23 [2] 36 3b [2] 71 39 [2] 36 28 [2] 78 24 [2] 74 2e [2] 63 25 [2] 78 6b [2] 45 }

  condition:
    any of them
}