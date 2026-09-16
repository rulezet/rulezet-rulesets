rule TTP_XOR_MULT_DOSStub_d4fe {
  strings:
    $key_d4fe = { 80 96 [2] f4 8e [2] b3 8c [2] f4 9d [2] ba 91 [2] b6 9b [2] a1 90 [2] ba de [2] 87 }

  condition:
    any of them
}