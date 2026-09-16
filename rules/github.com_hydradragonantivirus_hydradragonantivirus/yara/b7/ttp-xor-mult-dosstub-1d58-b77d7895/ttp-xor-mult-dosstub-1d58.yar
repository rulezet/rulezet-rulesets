rule TTP_XOR_MULT_DOSStub_1d58 {
  strings:
    $key_1d58 = { 49 30 [2] 3d 28 [2] 7a 2a [2] 3d 3b [2] 73 37 [2] 7f 3d [2] 68 36 [2] 73 78 [2] 4e }

  condition:
    any of them
}