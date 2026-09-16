rule TTP_XOR_MULT_DOSStub_d82c {
  strings:
    $key_d82c = { 8c 44 [2] f8 5c [2] bf 5e [2] f8 4f [2] b6 43 [2] ba 49 [2] ad 42 [2] b6 0c [2] 8b }

  condition:
    any of them
}