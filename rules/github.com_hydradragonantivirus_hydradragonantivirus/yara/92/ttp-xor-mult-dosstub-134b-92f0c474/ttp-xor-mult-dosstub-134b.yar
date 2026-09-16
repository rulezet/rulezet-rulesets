rule TTP_XOR_MULT_DOSStub_134b {
  strings:
    $key_134b = { 47 23 [2] 33 3b [2] 74 39 [2] 33 28 [2] 7d 24 [2] 71 2e [2] 66 25 [2] 7d 6b [2] 40 }

  condition:
    any of them
}