rule TTP_XOR_MULT_DOSStub_044c {
  strings:
    $key_044c = { 50 24 [2] 24 3c [2] 63 3e [2] 24 2f [2] 6a 23 [2] 66 29 [2] 71 22 [2] 6a 6c [2] 57 }

  condition:
    any of them
}