rule TTP_XOR_MULT_DOSStub_48e4 {
  strings:
    $key_48e4 = { 1c 8c [2] 68 94 [2] 2f 96 [2] 68 87 [2] 26 8b [2] 2a 81 [2] 3d 8a [2] 26 c4 [2] 1b }

  condition:
    any of them
}