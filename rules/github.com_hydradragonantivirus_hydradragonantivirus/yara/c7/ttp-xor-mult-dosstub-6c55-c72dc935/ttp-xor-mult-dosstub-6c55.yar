rule TTP_XOR_MULT_DOSStub_6c55 {
  strings:
    $key_6c55 = { 38 3d [2] 4c 25 [2] 0b 27 [2] 4c 36 [2] 02 3a [2] 0e 30 [2] 19 3b [2] 02 75 [2] 3f }

  condition:
    any of them
}