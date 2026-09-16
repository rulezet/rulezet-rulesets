rule TTP_XOR_MULT_DOSStub_d121 {
  strings:
    $key_d121 = { 85 49 [2] f1 51 [2] b6 53 [2] f1 42 [2] bf 4e [2] b3 44 [2] a4 4f [2] bf 01 [2] 82 }

  condition:
    any of them
}