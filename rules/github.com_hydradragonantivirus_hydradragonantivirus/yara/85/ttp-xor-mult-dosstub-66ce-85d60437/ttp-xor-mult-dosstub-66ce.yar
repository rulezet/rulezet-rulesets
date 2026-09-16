rule TTP_XOR_MULT_DOSStub_66ce {
  strings:
    $key_66ce = { 32 a6 [2] 46 be [2] 01 bc [2] 46 ad [2] 08 a1 [2] 04 ab [2] 13 a0 [2] 08 ee [2] 35 }

  condition:
    any of them
}