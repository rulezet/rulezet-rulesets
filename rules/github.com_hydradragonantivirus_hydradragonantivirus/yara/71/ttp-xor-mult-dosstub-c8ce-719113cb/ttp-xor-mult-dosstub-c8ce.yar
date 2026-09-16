rule TTP_XOR_MULT_DOSStub_c8ce {
  strings:
    $key_c8ce = { 9c a6 [2] e8 be [2] af bc [2] e8 ad [2] a6 a1 [2] aa ab [2] bd a0 [2] a6 ee [2] 9b }

  condition:
    any of them
}