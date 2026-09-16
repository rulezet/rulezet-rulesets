rule TTP_XOR_MULT_DOSStub_38ce {
  strings:
    $key_38ce = { 6c a6 [2] 18 be [2] 5f bc [2] 18 ad [2] 56 a1 [2] 5a ab [2] 4d a0 [2] 56 ee [2] 6b }

  condition:
    any of them
}