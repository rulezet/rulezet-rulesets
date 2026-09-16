rule TTP_XOR_MULT_DOSStub_4014 {
  strings:
    $key_4014 = { 14 7c [2] 60 64 [2] 27 66 [2] 60 77 [2] 2e 7b [2] 22 71 [2] 35 7a [2] 2e 34 [2] 13 }

  condition:
    any of them
}