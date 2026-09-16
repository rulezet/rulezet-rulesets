rule TTP_XOR_MULT_DOSStub_d1e5 {
  strings:
    $key_d1e5 = { 85 8d [2] f1 95 [2] b6 97 [2] f1 86 [2] bf 8a [2] b3 80 [2] a4 8b [2] bf c5 [2] 82 }

  condition:
    any of them
}