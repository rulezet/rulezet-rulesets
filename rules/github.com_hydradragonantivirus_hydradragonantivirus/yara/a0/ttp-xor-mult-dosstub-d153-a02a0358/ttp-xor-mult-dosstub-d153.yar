rule TTP_XOR_MULT_DOSStub_d153 {
  strings:
    $key_d153 = { 85 3b [2] f1 23 [2] b6 21 [2] f1 30 [2] bf 3c [2] b3 36 [2] a4 3d [2] bf 73 [2] 82 }

  condition:
    any of them
}