rule TTP_XOR_MULT_DOSStub_5a03 {
  strings:
    $key_5a03 = { 0e 6b [2] 7a 73 [2] 3d 71 [2] 7a 60 [2] 34 6c [2] 38 66 [2] 2f 6d [2] 34 23 [2] 09 }

  condition:
    any of them
}