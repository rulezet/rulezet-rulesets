rule TTP_XOR_MULT_DOSStub_374b {
  strings:
    $key_374b = { 63 23 [2] 17 3b [2] 50 39 [2] 17 28 [2] 59 24 [2] 55 2e [2] 42 25 [2] 59 6b [2] 64 }

  condition:
    any of them
}