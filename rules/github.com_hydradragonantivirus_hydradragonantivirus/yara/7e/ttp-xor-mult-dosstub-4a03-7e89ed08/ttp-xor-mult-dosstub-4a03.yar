rule TTP_XOR_MULT_DOSStub_4a03 {
  strings:
    $key_4a03 = { 1e 6b [2] 6a 73 [2] 2d 71 [2] 6a 60 [2] 24 6c [2] 28 66 [2] 3f 6d [2] 24 23 [2] 19 }

  condition:
    any of them
}