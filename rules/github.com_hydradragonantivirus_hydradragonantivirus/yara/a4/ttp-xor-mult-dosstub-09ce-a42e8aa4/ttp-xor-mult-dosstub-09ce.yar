rule TTP_XOR_MULT_DOSStub_09ce {
  strings:
    $key_09ce = { 5d a6 [2] 29 be [2] 6e bc [2] 29 ad [2] 67 a1 [2] 6b ab [2] 7c a0 [2] 67 ee [2] 5a }

  condition:
    any of them
}