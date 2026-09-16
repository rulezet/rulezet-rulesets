rule TTP_XOR_MULT_DOSStub_2ddf {
  strings:
    $key_2ddf = { 79 b7 [2] 0d af [2] 4a ad [2] 0d bc [2] 43 b0 [2] 4f ba [2] 58 b1 [2] 43 ff [2] 7e }

  condition:
    any of them
}