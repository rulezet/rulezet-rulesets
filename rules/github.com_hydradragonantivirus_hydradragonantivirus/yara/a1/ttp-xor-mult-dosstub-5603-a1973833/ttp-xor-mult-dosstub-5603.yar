rule TTP_XOR_MULT_DOSStub_5603 {
  strings:
    $key_5603 = { 02 6b [2] 76 73 [2] 31 71 [2] 76 60 [2] 38 6c [2] 34 66 [2] 23 6d [2] 38 23 [2] 05 }

  condition:
    any of them
}