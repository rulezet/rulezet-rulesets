rule TTP_XOR_MULT_DOSStub_5d58 {
  strings:
    $key_5d58 = { 09 30 [2] 7d 28 [2] 3a 2a [2] 7d 3b [2] 33 37 [2] 3f 3d [2] 28 36 [2] 33 78 [2] 0e }

  condition:
    any of them
}