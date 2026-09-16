rule TTP_XOR_MULT_DOSStub_ccdd {
  strings:
    $key_ccdd = { 98 b5 [2] ec ad [2] ab af [2] ec be [2] a2 b2 [2] ae b8 [2] b9 b3 [2] a2 fd [2] 9f }

  condition:
    any of them
}