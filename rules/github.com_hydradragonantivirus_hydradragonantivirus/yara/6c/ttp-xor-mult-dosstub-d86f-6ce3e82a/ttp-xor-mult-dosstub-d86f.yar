rule TTP_XOR_MULT_DOSStub_d86f {
  strings:
    $key_d86f = { 8c 07 [2] f8 1f [2] bf 1d [2] f8 0c [2] b6 00 [2] ba 0a [2] ad 01 [2] b6 4f [2] 8b }

  condition:
    any of them
}