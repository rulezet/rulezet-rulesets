rule TTP_XOR_MULT_DOSStub_3ddf {
  strings:
    $key_3ddf = { 69 b7 [2] 1d af [2] 5a ad [2] 1d bc [2] 53 b0 [2] 5f ba [2] 48 b1 [2] 53 ff [2] 6e }

  condition:
    any of them
}