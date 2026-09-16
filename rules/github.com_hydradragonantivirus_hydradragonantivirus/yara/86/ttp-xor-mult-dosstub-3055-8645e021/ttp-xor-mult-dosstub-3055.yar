rule TTP_XOR_MULT_DOSStub_3055 {
  strings:
    $key_3055 = { 64 3d [2] 10 25 [2] 57 27 [2] 10 36 [2] 5e 3a [2] 52 30 [2] 45 3b [2] 5e 75 [2] 63 }

  condition:
    any of them
}