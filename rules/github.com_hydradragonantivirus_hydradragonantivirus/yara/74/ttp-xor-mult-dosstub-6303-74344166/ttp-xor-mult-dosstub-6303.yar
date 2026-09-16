rule TTP_XOR_MULT_DOSStub_6303 {
  strings:
    $key_6303 = { 37 6b [2] 43 73 [2] 04 71 [2] 43 60 [2] 0d 6c [2] 01 66 [2] 16 6d [2] 0d 23 [2] 30 }

  condition:
    any of them
}