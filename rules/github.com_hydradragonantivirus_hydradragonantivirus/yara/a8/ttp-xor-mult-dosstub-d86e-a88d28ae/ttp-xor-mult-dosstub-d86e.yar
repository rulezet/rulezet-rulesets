rule TTP_XOR_MULT_DOSStub_d86e {
  strings:
    $key_d86e = { 8c 06 [2] f8 1e [2] bf 1c [2] f8 0d [2] b6 01 [2] ba 0b [2] ad 00 [2] b6 4e [2] 8b }

  condition:
    any of them
}