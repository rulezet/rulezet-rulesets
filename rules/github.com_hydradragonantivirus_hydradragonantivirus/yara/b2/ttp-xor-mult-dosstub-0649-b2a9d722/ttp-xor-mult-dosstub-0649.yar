rule TTP_XOR_MULT_DOSStub_0649 {
  strings:
    $key_0649 = { 52 21 [2] 26 39 [2] 61 3b [2] 26 2a [2] 68 26 [2] 64 2c [2] 73 27 [2] 68 69 [2] 55 }

  condition:
    any of them
}