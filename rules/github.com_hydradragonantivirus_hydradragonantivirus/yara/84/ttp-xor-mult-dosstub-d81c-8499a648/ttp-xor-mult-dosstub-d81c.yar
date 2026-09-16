rule TTP_XOR_MULT_DOSStub_d81c {
  strings:
    $key_d81c = { 8c 74 [2] f8 6c [2] bf 6e [2] f8 7f [2] b6 73 [2] ba 79 [2] ad 72 [2] b6 3c [2] 8b }

  condition:
    any of them
}