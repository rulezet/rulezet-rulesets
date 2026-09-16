rule TTP_XOR_MULT_DOSStub_7c55 {
  strings:
    $key_7c55 = { 28 3d [2] 5c 25 [2] 1b 27 [2] 5c 36 [2] 12 3a [2] 1e 30 [2] 09 3b [2] 12 75 [2] 2f }

  condition:
    any of them
}