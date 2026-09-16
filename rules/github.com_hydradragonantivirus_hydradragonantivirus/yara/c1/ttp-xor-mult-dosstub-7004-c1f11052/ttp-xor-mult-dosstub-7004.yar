rule TTP_XOR_MULT_DOSStub_7004 {
  strings:
    $key_7004 = { 24 6c [2] 50 74 [2] 17 76 [2] 50 67 [2] 1e 6b [2] 12 61 [2] 05 6a [2] 1e 24 [2] 23 }

  condition:
    any of them
}