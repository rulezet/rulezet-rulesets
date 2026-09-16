rule TTP_XOR_MULT_DOSStub_7473 {
  strings:
    $key_7473 = { 20 1b [2] 54 03 [2] 13 01 [2] 54 10 [2] 1a 1c [2] 16 16 [2] 01 1d [2] 1a 53 [2] 27 }

  condition:
    any of them
}