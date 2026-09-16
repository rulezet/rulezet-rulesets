rule TTP_XOR_MULT_DOSStub_701f {
  strings:
    $key_701f = { 24 77 [2] 50 6f [2] 17 6d [2] 50 7c [2] 1e 70 [2] 12 7a [2] 05 71 [2] 1e 3f [2] 23 }

  condition:
    any of them
}