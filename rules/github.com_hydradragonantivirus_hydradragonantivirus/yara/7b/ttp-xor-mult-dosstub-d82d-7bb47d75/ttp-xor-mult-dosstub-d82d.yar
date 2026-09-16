rule TTP_XOR_MULT_DOSStub_d82d {
  strings:
    $key_d82d = { 8c 45 [2] f8 5d [2] bf 5f [2] f8 4e [2] b6 42 [2] ba 48 [2] ad 43 [2] b6 0d [2] 8b }

  condition:
    any of them
}