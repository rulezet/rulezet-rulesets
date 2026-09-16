rule TTP_XOR_MULT_DOSStub_5412 {
  strings:
    $key_5412 = { 00 7a [2] 74 62 [2] 33 60 [2] 74 71 [2] 3a 7d [2] 36 77 [2] 21 7c [2] 3a 32 [2] 07 }

  condition:
    any of them
}