rule TTP_XOR_MULT_DOSStub_0645 {
  strings:
    $key_0645 = { 52 2d [2] 26 35 [2] 61 37 [2] 26 26 [2] 68 2a [2] 64 20 [2] 73 2b [2] 68 65 [2] 55 }

  condition:
    any of them
}