rule TTP_XOR_MULT_DOSStub_4dcc {
  strings:
    $key_4dcc = { 19 a4 [2] 6d bc [2] 2a be [2] 6d af [2] 23 a3 [2] 2f a9 [2] 38 a2 [2] 23 ec [2] 1e }

  condition:
    any of them
}