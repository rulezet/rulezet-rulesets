rule TTP_XOR_MULT_DOSStub_0803 {
  strings:
    $key_0803 = { 5c 6b [2] 28 73 [2] 6f 71 [2] 28 60 [2] 66 6c [2] 6a 66 [2] 7d 6d [2] 66 23 [2] 5b }

  condition:
    any of them
}