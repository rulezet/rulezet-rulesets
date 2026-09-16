rule TTP_XOR_MULT_DOSStub_7a12 {
  strings:
    $key_7a12 = { 2e 7a [2] 5a 62 [2] 1d 60 [2] 5a 71 [2] 14 7d [2] 18 77 [2] 0f 7c [2] 14 32 [2] 29 }

  condition:
    any of them
}