rule TTP_XOR_MULT_DOSStub_4412 {
  strings:
    $key_4412 = { 10 7a [2] 64 62 [2] 23 60 [2] 64 71 [2] 2a 7d [2] 26 77 [2] 31 7c [2] 2a 32 [2] 17 }

  condition:
    any of them
}