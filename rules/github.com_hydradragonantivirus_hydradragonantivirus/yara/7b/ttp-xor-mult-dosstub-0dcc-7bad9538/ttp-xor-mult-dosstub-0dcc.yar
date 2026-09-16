rule TTP_XOR_MULT_DOSStub_0dcc {
  strings:
    $key_0dcc = { 59 a4 [2] 2d bc [2] 6a be [2] 2d af [2] 63 a3 [2] 6f a9 [2] 78 a2 [2] 63 ec [2] 5e }

  condition:
    any of them
}