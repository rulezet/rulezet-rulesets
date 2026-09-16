rule TTP_XOR_MULT_DOSStub_4455 {
  strings:
    $key_4455 = { 10 3d [2] 64 25 [2] 23 27 [2] 64 36 [2] 2a 3a [2] 26 30 [2] 31 3b [2] 2a 75 [2] 17 }

  condition:
    any of them
}