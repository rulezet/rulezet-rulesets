rule TTP_XOR_MULT_DOSStub_7a58 {
  strings:
    $key_7a58 = { 2e 30 [2] 5a 28 [2] 1d 2a [2] 5a 3b [2] 14 37 [2] 18 3d [2] 0f 36 [2] 14 78 [2] 29 }

  condition:
    any of them
}