rule TTP_XOR_MULT_DOSStub_d82e {
  strings:
    $key_d82e = { 8c 46 [2] f8 5e [2] bf 5c [2] f8 4d [2] b6 41 [2] ba 4b [2] ad 40 [2] b6 0e [2] 8b }

  condition:
    any of them
}