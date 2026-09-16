rule TTP_XOR_MULT_DOSStub_5dcc {
  strings:
    $key_5dcc = { 09 a4 [2] 7d bc [2] 3a be [2] 7d af [2] 33 a3 [2] 3f a9 [2] 28 a2 [2] 33 ec [2] 0e }

  condition:
    any of them
}