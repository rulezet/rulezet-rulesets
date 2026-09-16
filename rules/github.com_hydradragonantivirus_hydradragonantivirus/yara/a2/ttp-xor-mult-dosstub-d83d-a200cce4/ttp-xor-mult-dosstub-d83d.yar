rule TTP_XOR_MULT_DOSStub_d83d {
  strings:
    $key_d83d = { 8c 55 [2] f8 4d [2] bf 4f [2] f8 5e [2] b6 52 [2] ba 58 [2] ad 53 [2] b6 1d [2] 8b }

  condition:
    any of them
}