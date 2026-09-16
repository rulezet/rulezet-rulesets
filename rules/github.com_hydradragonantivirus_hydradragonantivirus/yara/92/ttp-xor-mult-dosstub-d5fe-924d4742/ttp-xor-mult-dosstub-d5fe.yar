rule TTP_XOR_MULT_DOSStub_d5fe {
  strings:
    $key_d5fe = { 81 96 [2] f5 8e [2] b2 8c [2] f5 9d [2] bb 91 [2] b7 9b [2] a0 90 [2] bb de [2] 86 }

  condition:
    any of them
}