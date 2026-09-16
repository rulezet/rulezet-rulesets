rule TTP_XOR_MULT_DOSStub_3958 {
  strings:
    $key_3958 = { 6d 30 [2] 19 28 [2] 5e 2a [2] 19 3b [2] 57 37 [2] 5b 3d [2] 4c 36 [2] 57 78 [2] 6a }

  condition:
    any of them
}