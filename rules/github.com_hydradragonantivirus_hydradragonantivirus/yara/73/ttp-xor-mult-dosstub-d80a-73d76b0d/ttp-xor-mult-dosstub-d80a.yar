rule TTP_XOR_MULT_DOSStub_d80a {
  strings:
    $key_d80a = { 8c 62 [2] f8 7a [2] bf 78 [2] f8 69 [2] b6 65 [2] ba 6f [2] ad 64 [2] b6 2a [2] 8b }

  condition:
    any of them
}