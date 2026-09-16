rule TTP_XOR_MULT_DOSStub_d164 {
  strings:
    $key_d164 = { 85 0c [2] f1 14 [2] b6 16 [2] f1 07 [2] bf 0b [2] b3 01 [2] a4 0a [2] bf 44 [2] 82 }

  condition:
    any of them
}