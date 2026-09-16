rule TTP_XOR_MULT_DOSStub_d8ce {
  strings:
    $key_d8ce = { 8c a6 [2] f8 be [2] bf bc [2] f8 ad [2] b6 a1 [2] ba ab [2] ad a0 [2] b6 ee [2] 8b }

  condition:
    any of them
}