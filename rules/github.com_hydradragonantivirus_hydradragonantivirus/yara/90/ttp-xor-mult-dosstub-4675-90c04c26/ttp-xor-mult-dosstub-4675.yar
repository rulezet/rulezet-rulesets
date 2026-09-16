rule TTP_XOR_MULT_DOSStub_4675 {
  strings:
    $key_4675 = { 12 1d [2] 66 05 [2] 21 07 [2] 66 16 [2] 28 1a [2] 24 10 [2] 33 1b [2] 28 55 [2] 15 }

  condition:
    any of them
}