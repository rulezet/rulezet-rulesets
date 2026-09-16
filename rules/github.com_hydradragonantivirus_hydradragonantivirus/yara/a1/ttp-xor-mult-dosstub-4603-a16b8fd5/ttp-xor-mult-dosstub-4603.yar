rule TTP_XOR_MULT_DOSStub_4603 {
  strings:
    $key_4603 = { 12 6b [2] 66 73 [2] 21 71 [2] 66 60 [2] 28 6c [2] 24 66 [2] 33 6d [2] 28 23 [2] 15 }

  condition:
    any of them
}