rule TTP_XOR_MULT_DOSStub_1a12 {
  strings:
    $key_1a12 = { 4e 7a [2] 3a 62 [2] 7d 60 [2] 3a 71 [2] 74 7d [2] 78 77 [2] 6f 7c [2] 74 32 [2] 49 }

  condition:
    any of them
}