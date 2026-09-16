rule TTP_XOR_MULT_DOSStub_1c55 {
  strings:
    $key_1c55 = { 48 3d [2] 3c 25 [2] 7b 27 [2] 3c 36 [2] 72 3a [2] 7e 30 [2] 69 3b [2] 72 75 [2] 4f }

  condition:
    any of them
}