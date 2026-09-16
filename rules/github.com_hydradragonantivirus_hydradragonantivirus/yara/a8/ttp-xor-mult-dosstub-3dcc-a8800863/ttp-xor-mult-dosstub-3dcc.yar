rule TTP_XOR_MULT_DOSStub_3dcc {
  strings:
    $key_3dcc = { 69 a4 [2] 1d bc [2] 5a be [2] 1d af [2] 53 a3 [2] 5f a9 [2] 48 a2 [2] 53 ec [2] 6e }

  condition:
    any of them
}