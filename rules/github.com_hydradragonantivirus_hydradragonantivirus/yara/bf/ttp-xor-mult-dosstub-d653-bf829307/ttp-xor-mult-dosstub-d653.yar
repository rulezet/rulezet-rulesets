rule TTP_XOR_MULT_DOSStub_d653 {
  strings:
    $key_d653 = { 82 3b [2] f6 23 [2] b1 21 [2] f6 30 [2] b8 3c [2] b4 36 [2] a3 3d [2] b8 73 [2] 85 }

  condition:
    any of them
}