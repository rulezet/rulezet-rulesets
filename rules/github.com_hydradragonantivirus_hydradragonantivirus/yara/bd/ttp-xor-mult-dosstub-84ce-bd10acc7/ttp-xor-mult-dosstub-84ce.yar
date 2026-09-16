rule TTP_XOR_MULT_DOSStub_84ce {
  strings:
    $key_84ce = { d0 a6 [2] a4 be [2] e3 bc [2] a4 ad [2] ea a1 [2] e6 ab [2] f1 a0 [2] ea ee [2] d7 }

  condition:
    any of them
}