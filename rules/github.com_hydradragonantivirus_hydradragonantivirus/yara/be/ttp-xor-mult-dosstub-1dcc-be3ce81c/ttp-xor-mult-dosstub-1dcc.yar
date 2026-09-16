rule TTP_XOR_MULT_DOSStub_1dcc {
  strings:
    $key_1dcc = { 49 a4 [2] 3d bc [2] 7a be [2] 3d af [2] 73 a3 [2] 7f a9 [2] 68 a2 [2] 73 ec [2] 4e }

  condition:
    any of them
}