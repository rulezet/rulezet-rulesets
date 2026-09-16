rule TTP_XOR_MULT_DOSStub_d1f4 {
  strings:
    $key_d1f4 = { 85 9c [2] f1 84 [2] b6 86 [2] f1 97 [2] bf 9b [2] b3 91 [2] a4 9a [2] bf d4 [2] 82 }

  condition:
    any of them
}