rule TTP_XOR_MULT_DOSStub_d1fe {
  strings:
    $key_d1fe = { 85 96 [2] f1 8e [2] b6 8c [2] f1 9d [2] bf 91 [2] b3 9b [2] a4 90 [2] bf de [2] 82 }

  condition:
    any of them
}