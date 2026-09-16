rule TTP_XOR_MULT_DOSStub_e8ce {
  strings:
    $key_e8ce = { bc a6 [2] c8 be [2] 8f bc [2] c8 ad [2] 86 a1 [2] 8a ab [2] 9d a0 [2] 86 ee [2] bb }

  condition:
    any of them
}