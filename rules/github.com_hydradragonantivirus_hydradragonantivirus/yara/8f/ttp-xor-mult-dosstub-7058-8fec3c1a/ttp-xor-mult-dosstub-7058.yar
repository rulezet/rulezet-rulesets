rule TTP_XOR_MULT_DOSStub_7058 {
  strings:
    $key_7058 = { 24 30 [2] 50 28 [2] 17 2a [2] 50 3b [2] 1e 37 [2] 12 3d [2] 05 36 [2] 1e 78 [2] 23 }

  condition:
    any of them
}