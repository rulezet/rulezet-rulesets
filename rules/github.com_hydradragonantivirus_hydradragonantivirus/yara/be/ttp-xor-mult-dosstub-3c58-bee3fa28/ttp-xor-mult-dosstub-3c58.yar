rule TTP_XOR_MULT_DOSStub_3c58 {
  strings:
    $key_3c58 = { 68 30 [2] 1c 28 [2] 5b 2a [2] 1c 3b [2] 52 37 [2] 5e 3d [2] 49 36 [2] 52 78 [2] 6f }

  condition:
    any of them
}