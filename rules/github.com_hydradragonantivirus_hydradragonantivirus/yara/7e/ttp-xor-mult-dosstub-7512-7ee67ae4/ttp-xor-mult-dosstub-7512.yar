rule TTP_XOR_MULT_DOSStub_7512 {
  strings:
    $key_7512 = { 21 7a [2] 55 62 [2] 12 60 [2] 55 71 [2] 1b 7d [2] 17 77 [2] 00 7c [2] 1b 32 [2] 26 }

  condition:
    any of them
}