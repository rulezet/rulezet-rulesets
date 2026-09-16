rule TTP_XOR_MULT_DOSStub_d860 {
  strings:
    $key_d860 = { 8c 08 [2] f8 10 [2] bf 12 [2] f8 03 [2] b6 0f [2] ba 05 [2] ad 0e [2] b6 40 [2] 8b }

  condition:
    any of them
}