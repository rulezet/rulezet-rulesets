rule TTP_XOR_MULT_DOSStub_0075 {
  strings:
    $key_0075 = { 54 1d [2] 20 05 [2] 67 07 [2] 20 16 [2] 6e 1a [2] 62 10 [2] 75 1b [2] 6e 55 [2] 53 }

  condition:
    any of them
}