rule TTP_XOR_MULT_DOSStub_d0ce {
  strings:
    $key_d0ce = { 84 a6 [2] f0 be [2] b7 bc [2] f0 ad [2] be a1 [2] b2 ab [2] a5 a0 [2] be ee [2] 83 }

  condition:
    any of them
}