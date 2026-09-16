rule TTP_XOR_MULT_DOSStub_7a03 {
  strings:
    $key_7a03 = { 2e 6b [2] 5a 73 [2] 1d 71 [2] 5a 60 [2] 14 6c [2] 18 66 [2] 0f 6d [2] 14 23 [2] 29 }

  condition:
    any of them
}