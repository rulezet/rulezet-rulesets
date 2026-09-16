rule TTP_XOR_MULT_DOSStub_d123 {
  strings:
    $key_d123 = { 85 4b [2] f1 53 [2] b6 51 [2] f1 40 [2] bf 4c [2] b3 46 [2] a4 4d [2] bf 03 [2] 82 }

  condition:
    any of them
}