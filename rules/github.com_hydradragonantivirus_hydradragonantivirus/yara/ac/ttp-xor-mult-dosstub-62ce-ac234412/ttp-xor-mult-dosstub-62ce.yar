rule TTP_XOR_MULT_DOSStub_62ce {
  strings:
    $key_62ce = { 36 a6 [2] 42 be [2] 05 bc [2] 42 ad [2] 0c a1 [2] 00 ab [2] 17 a0 [2] 0c ee [2] 31 }

  condition:
    any of them
}