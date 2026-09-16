rule TTP_XOR_MULT_DOSStub_d80c {
  strings:
    $key_d80c = { 8c 64 [2] f8 7c [2] bf 7e [2] f8 6f [2] b6 63 [2] ba 69 [2] ad 62 [2] b6 2c [2] 8b }

  condition:
    any of them
}