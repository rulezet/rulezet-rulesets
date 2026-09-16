rule TTP_XOR_MULT_DOSStub_d81e {
  strings:
    $key_d81e = { 8c 76 [2] f8 6e [2] bf 6c [2] f8 7d [2] b6 71 [2] ba 7b [2] ad 70 [2] b6 3e [2] 8b }

  condition:
    any of them
}