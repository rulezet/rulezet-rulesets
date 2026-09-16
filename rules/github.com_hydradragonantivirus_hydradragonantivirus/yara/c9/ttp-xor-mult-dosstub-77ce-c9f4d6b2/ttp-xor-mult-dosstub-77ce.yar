rule TTP_XOR_MULT_DOSStub_77ce {
  strings:
    $key_77ce = { 23 a6 [2] 57 be [2] 10 bc [2] 57 ad [2] 19 a1 [2] 15 ab [2] 02 a0 [2] 19 ee [2] 24 }

  condition:
    any of them
}