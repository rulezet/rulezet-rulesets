rule TTP_XOR_MULT_DOSStub_d10e {
  strings:
    $key_d10e = { 85 66 [2] f1 7e [2] b6 7c [2] f1 6d [2] bf 61 [2] b3 6b [2] a4 60 [2] bf 2e [2] 82 }

  condition:
    any of them
}