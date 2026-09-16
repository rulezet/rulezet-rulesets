rule TTP_XOR_MULT_DOSStub_d83e {
  strings:
    $key_d83e = { 8c 56 [2] f8 4e [2] bf 4c [2] f8 5d [2] b6 51 [2] ba 5b [2] ad 50 [2] b6 1e [2] 8b }

  condition:
    any of them
}