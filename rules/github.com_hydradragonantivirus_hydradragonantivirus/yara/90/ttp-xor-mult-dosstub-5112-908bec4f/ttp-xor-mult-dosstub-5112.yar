rule TTP_XOR_MULT_DOSStub_5112 {
  strings:
    $key_5112 = { 05 7a [2] 71 62 [2] 36 60 [2] 71 71 [2] 3f 7d [2] 33 77 [2] 24 7c [2] 3f 32 [2] 02 }

  condition:
    any of them
}