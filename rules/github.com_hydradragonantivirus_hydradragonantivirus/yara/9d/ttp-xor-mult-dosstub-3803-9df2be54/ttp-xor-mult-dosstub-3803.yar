rule TTP_XOR_MULT_DOSStub_3803 {
  strings:
    $key_3803 = { 6c 6b [2] 18 73 [2] 5f 71 [2] 18 60 [2] 56 6c [2] 5a 66 [2] 4d 6d [2] 56 23 [2] 6b }

  condition:
    any of them
}