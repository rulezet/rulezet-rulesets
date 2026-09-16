rule TTP_XOR_MULT_DOSStub_1e58 {
  strings:
    $key_1e58 = { 4a 30 [2] 3e 28 [2] 79 2a [2] 3e 3b [2] 70 37 [2] 7c 3d [2] 6b 36 [2] 70 78 [2] 4d }

  condition:
    any of them
}