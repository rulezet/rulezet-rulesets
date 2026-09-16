rule TTP_XOR_MULT_DOSStub_abce {
  strings:
    $key_abce = { ff a6 [2] 8b be [2] cc bc [2] 8b ad [2] c5 a1 [2] c9 ab [2] de a0 [2] c5 ee [2] f8 }

  condition:
    any of them
}