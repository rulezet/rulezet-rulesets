rule TTP_XOR_MULT_DOSStub_ee89 {
  strings:
    $key_ee89 = { ba e1 [2] ce f9 [2] 89 fb [2] ce ea [2] 80 e6 [2] 8c ec [2] 9b e7 [2] 80 a9 [2] bd }

  condition:
    any of them
}