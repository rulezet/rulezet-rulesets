rule TTP_XOR_MULT_DOSStub_d13b {
  strings:
    $key_d13b = { 85 53 [2] f1 4b [2] b6 49 [2] f1 58 [2] bf 54 [2] b3 5e [2] a4 55 [2] bf 1b [2] 82 }

  condition:
    any of them
}