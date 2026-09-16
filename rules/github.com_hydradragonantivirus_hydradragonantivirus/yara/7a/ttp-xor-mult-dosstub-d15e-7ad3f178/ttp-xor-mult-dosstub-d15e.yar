rule TTP_XOR_MULT_DOSStub_d15e {
  strings:
    $key_d15e = { 85 36 [2] f1 2e [2] b6 2c [2] f1 3d [2] bf 31 [2] b3 3b [2] a4 30 [2] bf 7e [2] 82 }

  condition:
    any of them
}