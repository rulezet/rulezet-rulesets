rule TTP_XOR_MULT_DOSStub_d84c {
  strings:
    $key_d84c = { 8c 24 [2] f8 3c [2] bf 3e [2] f8 2f [2] b6 23 [2] ba 29 [2] ad 22 [2] b6 6c [2] 8b }

  condition:
    any of them
}