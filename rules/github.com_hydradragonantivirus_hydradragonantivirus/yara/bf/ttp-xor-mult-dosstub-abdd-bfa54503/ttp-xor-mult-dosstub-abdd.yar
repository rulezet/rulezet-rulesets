rule TTP_XOR_MULT_DOSStub_abdd {
  strings:
    $key_abdd = { ff b5 [2] 8b ad [2] cc af [2] 8b be [2] c5 b2 [2] c9 b8 [2] de b3 [2] c5 fd [2] f8 }

  condition:
    any of them
}