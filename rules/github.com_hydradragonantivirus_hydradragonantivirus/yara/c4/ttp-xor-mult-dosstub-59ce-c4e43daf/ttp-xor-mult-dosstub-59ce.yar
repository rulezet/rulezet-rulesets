rule TTP_XOR_MULT_DOSStub_59ce {
  strings:
    $key_59ce = { 0d a6 [2] 79 be [2] 3e bc [2] 79 ad [2] 37 a1 [2] 3b ab [2] 2c a0 [2] 37 ee [2] 0a }

  condition:
    any of them
}