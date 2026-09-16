rule TTP_XOR_MULT_DOSStub_d1ec {
  strings:
    $key_d1ec = { 85 84 [2] f1 9c [2] b6 9e [2] f1 8f [2] bf 83 [2] b3 89 [2] a4 82 [2] bf cc [2] 82 }

  condition:
    any of them
}