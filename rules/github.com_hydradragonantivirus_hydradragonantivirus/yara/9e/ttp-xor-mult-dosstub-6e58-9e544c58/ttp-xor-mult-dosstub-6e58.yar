rule TTP_XOR_MULT_DOSStub_6e58 {
  strings:
    $key_6e58 = { 3a 30 [2] 4e 28 [2] 09 2a [2] 4e 3b [2] 00 37 [2] 0c 3d [2] 1b 36 [2] 00 78 [2] 3d }

  condition:
    any of them
}