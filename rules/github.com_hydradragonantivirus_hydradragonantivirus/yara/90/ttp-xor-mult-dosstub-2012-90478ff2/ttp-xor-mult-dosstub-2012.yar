rule TTP_XOR_MULT_DOSStub_2012 {
  strings:
    $key_2012 = { 74 7a [2] 00 62 [2] 47 60 [2] 00 71 [2] 4e 7d [2] 42 77 [2] 55 7c [2] 4e 32 [2] 73 }

  condition:
    any of them
}