rule TTP_XOR_MULT_DOSStub_0072 {
  strings:
    $key_0072 = { 54 1a [2] 20 02 [2] 67 00 [2] 20 11 [2] 6e 1d [2] 62 17 [2] 75 1c [2] 6e 52 [2] 53 }

  condition:
    any of them
}