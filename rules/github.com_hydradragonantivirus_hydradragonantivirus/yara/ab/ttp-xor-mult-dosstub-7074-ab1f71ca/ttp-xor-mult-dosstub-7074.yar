rule TTP_XOR_MULT_DOSStub_7074 {
  strings:
    $key_7074 = { 24 1c [2] 50 04 [2] 17 06 [2] 50 17 [2] 1e 1b [2] 12 11 [2] 05 1a [2] 1e 54 [2] 23 }

  condition:
    any of them
}