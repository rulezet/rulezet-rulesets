rule TTP_XOR_MULT_DOSStub_6a58 {
  strings:
    $key_6a58 = { 3e 30 [2] 4a 28 [2] 0d 2a [2] 4a 3b [2] 04 37 [2] 08 3d [2] 1f 36 [2] 04 78 [2] 39 }

  condition:
    any of them
}