rule TTP_XOR_MULT_DOSStub_464b {
  strings:
    $key_464b = { 12 23 [2] 66 3b [2] 21 39 [2] 66 28 [2] 28 24 [2] 24 2e [2] 33 25 [2] 28 6b [2] 15 }

  condition:
    any of them
}