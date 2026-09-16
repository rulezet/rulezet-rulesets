rule TTP_XOR_MULT_DOSStub_7008 {
  strings:
    $key_7008 = { 24 60 [2] 50 78 [2] 17 7a [2] 50 6b [2] 1e 67 [2] 12 6d [2] 05 66 [2] 1e 28 [2] 23 }

  condition:
    any of them
}