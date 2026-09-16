rule TTP_XOR_MULT_DOSStub_b7ce {
  strings:
    $key_b7ce = { e3 a6 [2] 97 be [2] d0 bc [2] 97 ad [2] d9 a1 [2] d5 ab [2] c2 a0 [2] d9 ee [2] e4 }

  condition:
    any of them
}