rule TTP_XOR_MULT_DOSStub_12ce {
  strings:
    $key_12ce = { 46 a6 [2] 32 be [2] 75 bc [2] 32 ad [2] 7c a1 [2] 70 ab [2] 67 a0 [2] 7c ee [2] 41 }

  condition:
    any of them
}