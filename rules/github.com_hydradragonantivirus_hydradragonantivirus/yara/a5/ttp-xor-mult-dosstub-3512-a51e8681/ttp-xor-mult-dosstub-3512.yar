rule TTP_XOR_MULT_DOSStub_3512 {
  strings:
    $key_3512 = { 61 7a [2] 15 62 [2] 52 60 [2] 15 71 [2] 5b 7d [2] 57 77 [2] 40 7c [2] 5b 32 [2] 66 }

  condition:
    any of them
}