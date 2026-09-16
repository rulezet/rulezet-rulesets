rule TTP_XOR_MULT_DOSStub_404b {
  strings:
    $key_404b = { 14 23 [2] 60 3b [2] 27 39 [2] 60 28 [2] 2e 24 [2] 22 2e [2] 35 25 [2] 2e 6b [2] 13 }

  condition:
    any of them
}