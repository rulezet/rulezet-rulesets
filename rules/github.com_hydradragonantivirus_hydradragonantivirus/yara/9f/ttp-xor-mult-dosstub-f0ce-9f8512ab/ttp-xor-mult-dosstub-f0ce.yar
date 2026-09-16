rule TTP_XOR_MULT_DOSStub_f0ce {
  strings:
    $key_f0ce = { a4 a6 [2] d0 be [2] 97 bc [2] d0 ad [2] 9e a1 [2] 92 ab [2] 85 a0 [2] 9e ee [2] a3 }

  condition:
    any of them
}