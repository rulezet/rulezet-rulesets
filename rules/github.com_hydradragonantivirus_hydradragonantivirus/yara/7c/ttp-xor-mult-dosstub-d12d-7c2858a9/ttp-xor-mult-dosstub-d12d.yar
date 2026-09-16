rule TTP_XOR_MULT_DOSStub_d12d {
  strings:
    $key_d12d = { 85 45 [2] f1 5d [2] b6 5f [2] f1 4e [2] bf 42 [2] b3 48 [2] a4 43 [2] bf 0d [2] 82 }

  condition:
    any of them
}