rule TTP_XOR_MULT_DOSStub_d15c {
  strings:
    $key_d15c = { 85 34 [2] f1 2c [2] b6 2e [2] f1 3f [2] bf 33 [2] b3 39 [2] a4 32 [2] bf 7c [2] 82 }

  condition:
    any of them
}