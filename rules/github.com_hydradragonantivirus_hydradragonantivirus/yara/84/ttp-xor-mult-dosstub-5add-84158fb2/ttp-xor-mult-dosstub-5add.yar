rule TTP_XOR_MULT_DOSStub_5add {
  strings:
    $key_5add = { 0e b5 [2] 7a ad [2] 3d af [2] 7a be [2] 34 b2 [2] 38 b8 [2] 2f b3 [2] 34 fd [2] 09 }

  condition:
    any of them
}