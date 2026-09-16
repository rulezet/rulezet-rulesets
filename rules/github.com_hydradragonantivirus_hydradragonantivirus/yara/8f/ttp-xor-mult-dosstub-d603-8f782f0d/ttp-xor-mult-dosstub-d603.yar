rule TTP_XOR_MULT_DOSStub_d603 {
  strings:
    $key_d603 = { 82 6b [2] f6 73 [2] b1 71 [2] f6 60 [2] b8 6c [2] b4 66 [2] a3 6d [2] b8 23 [2] 85 }

  condition:
    any of them
}