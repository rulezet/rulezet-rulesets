rule TTP_XOR_MULT_DOSStub_d85c {
  strings:
    $key_d85c = { 8c 34 [2] f8 2c [2] bf 2e [2] f8 3f [2] b6 33 [2] ba 39 [2] ad 32 [2] b6 7c [2] 8b }

  condition:
    any of them
}