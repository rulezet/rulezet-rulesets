rule TTP_XOR_MULT_DOSStub_7002 {
  strings:
    $key_7002 = { 24 6a [2] 50 72 [2] 17 70 [2] 50 61 [2] 1e 6d [2] 12 67 [2] 05 6c [2] 1e 22 [2] 23 }

  condition:
    any of them
}