rule TTP_XOR_MULT_DOSStub_2744 {
  strings:
    $key_2744 = { 73 2c [2] 07 34 [2] 40 36 [2] 07 27 [2] 49 2b [2] 45 21 [2] 52 2a [2] 49 64 [2] 74 }

  condition:
    any of them
}