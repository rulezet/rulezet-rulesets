rule TTP_XOR_MULT_DOSStub_bcdf {
  strings:
    $key_bcdf = { e8 b7 [2] 9c af [2] db ad [2] 9c bc [2] d2 b0 [2] de ba [2] c9 b1 [2] d2 ff [2] ef }

  condition:
    any of them
}