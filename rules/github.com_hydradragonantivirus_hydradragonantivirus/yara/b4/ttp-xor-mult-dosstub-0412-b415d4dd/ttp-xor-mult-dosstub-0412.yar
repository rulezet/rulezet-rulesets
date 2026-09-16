rule TTP_XOR_MULT_DOSStub_0412 {
  strings:
    $key_0412 = { 50 7a [2] 24 62 [2] 63 60 [2] 24 71 [2] 6a 7d [2] 66 77 [2] 71 7c [2] 6a 32 [2] 57 }

  condition:
    any of them
}