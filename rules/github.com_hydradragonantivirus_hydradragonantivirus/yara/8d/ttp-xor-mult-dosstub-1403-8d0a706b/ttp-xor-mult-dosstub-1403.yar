rule TTP_XOR_MULT_DOSStub_1403 {
  strings:
    $key_1403 = { 40 6b [2] 34 73 [2] 73 71 [2] 34 60 [2] 7a 6c [2] 76 66 [2] 61 6d [2] 7a 23 [2] 47 }

  condition:
    any of them
}