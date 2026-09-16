rule TTP_XOR_MULT_DOSStub_72ce {
  strings:
    $key_72ce = { 26 a6 [2] 52 be [2] 15 bc [2] 52 ad [2] 1c a1 [2] 10 ab [2] 07 a0 [2] 1c ee [2] 21 }

  condition:
    any of them
}