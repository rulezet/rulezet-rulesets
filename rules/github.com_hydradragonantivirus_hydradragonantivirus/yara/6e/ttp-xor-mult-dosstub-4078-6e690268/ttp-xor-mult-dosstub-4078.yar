rule TTP_XOR_MULT_DOSStub_4078 {
  strings:
    $key_4078 = { 14 10 [2] 60 08 [2] 27 0a [2] 60 1b [2] 2e 17 [2] 22 1d [2] 35 16 [2] 2e 58 [2] 13 }

  condition:
    any of them
}