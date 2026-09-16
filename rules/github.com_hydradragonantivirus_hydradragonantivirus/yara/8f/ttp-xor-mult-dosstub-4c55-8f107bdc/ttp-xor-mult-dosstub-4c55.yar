rule TTP_XOR_MULT_DOSStub_4c55 {
  strings:
    $key_4c55 = { 18 3d [2] 6c 25 [2] 2b 27 [2] 6c 36 [2] 22 3a [2] 2e 30 [2] 39 3b [2] 22 75 [2] 1f }

  condition:
    any of them
}