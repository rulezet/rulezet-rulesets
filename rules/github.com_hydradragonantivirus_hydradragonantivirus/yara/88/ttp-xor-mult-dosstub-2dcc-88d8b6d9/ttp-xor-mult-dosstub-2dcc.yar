rule TTP_XOR_MULT_DOSStub_2dcc {
  strings:
    $key_2dcc = { 79 a4 [2] 0d bc [2] 4a be [2] 0d af [2] 43 a3 [2] 4f a9 [2] 58 a2 [2] 43 ec [2] 7e }

  condition:
    any of them
}