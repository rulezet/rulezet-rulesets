rule TTP_XOR_MULT_DOSStub_c9ce {
  strings:
    $key_c9ce = { 9d a6 [2] e9 be [2] ae bc [2] e9 ad [2] a7 a1 [2] ab ab [2] bc a0 [2] a7 ee [2] 9a }

  condition:
    any of them
}