rule TTP_XOR_MULT_DOSStub_0812 {
  strings:
    $key_0812 = { 5c 7a [2] 28 62 [2] 6f 60 [2] 28 71 [2] 66 7d [2] 6a 77 [2] 7d 7c [2] 66 32 [2] 5b }

  condition:
    any of them
}