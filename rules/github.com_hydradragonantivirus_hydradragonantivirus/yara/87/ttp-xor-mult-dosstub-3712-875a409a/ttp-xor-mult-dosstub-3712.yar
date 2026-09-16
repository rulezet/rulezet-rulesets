rule TTP_XOR_MULT_DOSStub_3712 {
  strings:
    $key_3712 = { 63 7a [2] 17 62 [2] 50 60 [2] 17 71 [2] 59 7d [2] 55 77 [2] 42 7c [2] 59 32 [2] 64 }

  condition:
    any of them
}