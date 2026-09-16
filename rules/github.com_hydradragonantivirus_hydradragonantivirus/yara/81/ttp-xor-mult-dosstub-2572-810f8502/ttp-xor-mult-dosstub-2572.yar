rule TTP_XOR_MULT_DOSStub_2572 {
  strings:
    $key_2572 = { 71 1a [2] 05 02 [2] 42 00 [2] 05 11 [2] 4b 1d [2] 47 17 [2] 50 1c [2] 4b 52 [2] 76 }

  condition:
    any of them
}