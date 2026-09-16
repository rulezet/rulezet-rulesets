rule TTP_XOR_MULT_DOSStub_6add {
  strings:
    $key_6add = { 3e b5 [2] 4a ad [2] 0d af [2] 4a be [2] 04 b2 [2] 08 b8 [2] 1f b3 [2] 04 fd [2] 39 }

  condition:
    any of them
}