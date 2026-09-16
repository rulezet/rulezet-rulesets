rule TTP_XOR_MULT_DOSStub_28ce {
  strings:
    $key_28ce = { 7c a6 [2] 08 be [2] 4f bc [2] 08 ad [2] 46 a1 [2] 4a ab [2] 5d a0 [2] 46 ee [2] 7b }

  condition:
    any of them
}