rule TTP_XOR_MULT_DOSStub_d80f {
  strings:
    $key_d80f = { 8c 67 [2] f8 7f [2] bf 7d [2] f8 6c [2] b6 60 [2] ba 6a [2] ad 61 [2] b6 2f [2] 8b }

  condition:
    any of them
}