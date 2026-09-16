rule TTP_XOR_MULT_DOSStub_ccce {
  strings:
    $key_ccce = { 98 a6 [2] ec be [2] ab bc [2] ec ad [2] a2 a1 [2] ae ab [2] b9 a0 [2] a2 ee [2] 9f }

  condition:
    any of them
}