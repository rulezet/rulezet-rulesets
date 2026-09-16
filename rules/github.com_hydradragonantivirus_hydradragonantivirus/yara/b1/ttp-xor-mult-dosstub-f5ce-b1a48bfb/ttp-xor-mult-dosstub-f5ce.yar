rule TTP_XOR_MULT_DOSStub_f5ce {
  strings:
    $key_f5ce = { a1 a6 [2] d5 be [2] 92 bc [2] d5 ad [2] 9b a1 [2] 97 ab [2] 80 a0 [2] 9b ee [2] a6 }

  condition:
    any of them
}