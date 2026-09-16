rule TTP_XOR_MULT_DOSStub_f4ce {
  strings:
    $key_f4ce = { a0 a6 [2] d4 be [2] 93 bc [2] d4 ad [2] 9a a1 [2] 96 ab [2] 81 a0 [2] 9a ee [2] a7 }

  condition:
    any of them
}