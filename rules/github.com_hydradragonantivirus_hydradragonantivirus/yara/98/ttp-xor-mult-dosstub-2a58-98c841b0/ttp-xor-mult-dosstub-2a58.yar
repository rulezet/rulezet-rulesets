rule TTP_XOR_MULT_DOSStub_2a58 {
  strings:
    $key_2a58 = { 7e 30 [2] 0a 28 [2] 4d 2a [2] 0a 3b [2] 44 37 [2] 48 3d [2] 5f 36 [2] 44 78 [2] 79 }

  condition:
    any of them
}