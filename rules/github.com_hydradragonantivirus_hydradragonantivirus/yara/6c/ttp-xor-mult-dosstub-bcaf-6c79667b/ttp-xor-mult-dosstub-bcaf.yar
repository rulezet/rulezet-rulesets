rule TTP_XOR_MULT_DOSStub_bcaf {
  strings:
    $key_bcaf = { e8 c7 [2] 9c df [2] db dd [2] 9c cc [2] d2 c0 [2] de ca [2] c9 c1 [2] d2 8f [2] ef }

  condition:
    any of them
}