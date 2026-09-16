rule TTP_XOR_MULT_DOSStub_a003 {
  strings:
    $key_a003 = { f4 6b [2] 80 73 [2] c7 71 [2] 80 60 [2] ce 6c [2] c2 66 [2] d5 6d [2] ce 23 [2] f3 }

  condition:
    any of them
}