rule TTP_XOR_MULT_DOSStub_abdc {
  strings:
    $key_abdc = { ff b4 [2] 8b ac [2] cc ae [2] 8b bf [2] c5 b3 [2] c9 b9 [2] de b2 [2] c5 fc [2] f8 }

  condition:
    any of them
}