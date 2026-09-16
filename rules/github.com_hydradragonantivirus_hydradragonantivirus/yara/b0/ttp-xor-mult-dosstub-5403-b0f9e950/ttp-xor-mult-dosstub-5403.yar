rule TTP_XOR_MULT_DOSStub_5403 {
  strings:
    $key_5403 = { 00 6b [2] 74 73 [2] 33 71 [2] 74 60 [2] 3a 6c [2] 36 66 [2] 21 6d [2] 3a 23 [2] 07 }

  condition:
    any of them
}