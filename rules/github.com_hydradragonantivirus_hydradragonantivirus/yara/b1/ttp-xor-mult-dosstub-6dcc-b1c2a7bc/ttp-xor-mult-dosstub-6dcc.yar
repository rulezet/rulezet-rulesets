rule TTP_XOR_MULT_DOSStub_6dcc {
  strings:
    $key_6dcc = { 39 a4 [2] 4d bc [2] 0a be [2] 4d af [2] 03 a3 [2] 0f a9 [2] 18 a2 [2] 03 ec [2] 3e }

  condition:
    any of them
}