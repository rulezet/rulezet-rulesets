rule TTP_XOR_MULT_DOSStub_d173 {
  strings:
    $key_d173 = { 85 1b [2] f1 03 [2] b6 01 [2] f1 10 [2] bf 1c [2] b3 16 [2] a4 1d [2] bf 53 [2] 82 }

  condition:
    any of them
}