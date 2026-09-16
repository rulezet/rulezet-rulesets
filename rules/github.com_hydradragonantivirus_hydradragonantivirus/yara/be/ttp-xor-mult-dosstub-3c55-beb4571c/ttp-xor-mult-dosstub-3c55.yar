rule TTP_XOR_MULT_DOSStub_3c55 {
  strings:
    $key_3c55 = { 68 3d [2] 1c 25 [2] 5b 27 [2] 1c 36 [2] 52 3a [2] 5e 30 [2] 49 3b [2] 52 75 [2] 6f }

  condition:
    any of them
}