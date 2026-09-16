rule TTP_XOR_MULT_DOSStub_045b {
  strings:
    $key_045b = { 50 33 [2] 24 2b [2] 63 29 [2] 24 38 [2] 6a 34 [2] 66 3e [2] 71 35 [2] 6a 7b [2] 57 }

  condition:
    any of them
}