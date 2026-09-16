rule TTP_XOR_MULT_DOSStub_4045 {
  strings:
    $key_4045 = { 14 2d [2] 60 35 [2] 27 37 [2] 60 26 [2] 2e 2a [2] 22 20 [2] 35 2b [2] 2e 65 [2] 13 }

  condition:
    any of them
}