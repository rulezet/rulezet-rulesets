rule TTP_XOR_MULT_DOSStub_7009 {
  strings:
    $key_7009 = { 24 61 [2] 50 79 [2] 17 7b [2] 50 6a [2] 1e 66 [2] 12 6c [2] 05 67 [2] 1e 29 [2] 23 }

  condition:
    any of them
}