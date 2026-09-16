rule TTP_XOR_MULT_DOSStub_4d58 {
  strings:
    $key_4d58 = { 19 30 [2] 6d 28 [2] 2a 2a [2] 6d 3b [2] 23 37 [2] 2f 3d [2] 38 36 [2] 23 78 [2] 1e }

  condition:
    any of them
}