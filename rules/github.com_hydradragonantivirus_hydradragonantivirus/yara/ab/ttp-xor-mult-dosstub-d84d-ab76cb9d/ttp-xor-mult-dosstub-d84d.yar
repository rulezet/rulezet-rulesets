rule TTP_XOR_MULT_DOSStub_d84d {
  strings:
    $key_d84d = { 8c 25 [2] f8 3d [2] bf 3f [2] f8 2e [2] b6 22 [2] ba 28 [2] ad 23 [2] b6 6d [2] 8b }

  condition:
    any of them
}