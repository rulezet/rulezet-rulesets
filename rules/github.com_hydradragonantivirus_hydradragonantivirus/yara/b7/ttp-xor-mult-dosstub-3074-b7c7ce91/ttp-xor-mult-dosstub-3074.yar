rule TTP_XOR_MULT_DOSStub_3074 {
  strings:
    $key_3074 = { 64 1c [2] 10 04 [2] 57 06 [2] 10 17 [2] 5e 1b [2] 52 11 [2] 45 1a [2] 5e 54 [2] 63 }

  condition:
    any of them
}