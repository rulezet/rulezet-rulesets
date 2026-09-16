rule TTP_XOR_MULT_DOSStub_7745 {
  strings:
    $key_7745 = { 23 2d [2] 57 35 [2] 10 37 [2] 57 26 [2] 19 2a [2] 15 20 [2] 02 2b [2] 19 65 [2] 24 }

  condition:
    any of them
}