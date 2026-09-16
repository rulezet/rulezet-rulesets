rule TTP_XOR_MULT_DOSStub_d8fe {
  strings:
    $key_d8fe = { 8c 96 [2] f8 8e [2] bf 8c [2] f8 9d [2] b6 91 [2] ba 9b [2] ad 90 [2] b6 de [2] 8b }

  condition:
    any of them
}