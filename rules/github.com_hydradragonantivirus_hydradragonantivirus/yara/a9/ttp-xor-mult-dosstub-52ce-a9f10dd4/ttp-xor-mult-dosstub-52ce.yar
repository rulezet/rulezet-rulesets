rule TTP_XOR_MULT_DOSStub_52ce {
  strings:
    $key_52ce = { 06 a6 [2] 72 be [2] 35 bc [2] 72 ad [2] 3c a1 [2] 30 ab [2] 27 a0 [2] 3c ee [2] 01 }

  condition:
    any of them
}