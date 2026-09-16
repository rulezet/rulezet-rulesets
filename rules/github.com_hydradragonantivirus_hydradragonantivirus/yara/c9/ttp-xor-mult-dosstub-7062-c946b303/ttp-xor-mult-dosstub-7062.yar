rule TTP_XOR_MULT_DOSStub_7062 {
  strings:
    $key_7062 = { 24 0a [2] 50 12 [2] 17 10 [2] 50 01 [2] 1e 0d [2] 12 07 [2] 05 0c [2] 1e 42 [2] 23 }

  condition:
    any of them
}