rule TTP_XOR_MULT_DOSStub_08ce {
  strings:
    $key_08ce = { 5c a6 [2] 28 be [2] 6f bc [2] 28 ad [2] 66 a1 [2] 6a ab [2] 7d a0 [2] 66 ee [2] 5b }

  condition:
    any of them
}