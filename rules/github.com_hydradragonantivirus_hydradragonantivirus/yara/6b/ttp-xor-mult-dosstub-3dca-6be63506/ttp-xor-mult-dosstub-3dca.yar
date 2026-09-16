rule TTP_XOR_MULT_DOSStub_3dca {
  strings:
    $key_3dca = { 69 a2 [2] 1d ba [2] 5a b8 [2] 1d a9 [2] 53 a5 [2] 5f af [2] 48 a4 [2] 53 ea [2] 6e }

  condition:
    any of them
}