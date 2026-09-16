rule TTP_XOR_MULT_DOSStub_4acc {
  strings:
    $key_4acc = { 1e a4 [2] 6a bc [2] 2d be [2] 6a af [2] 24 a3 [2] 28 a9 [2] 3f a2 [2] 24 ec [2] 19 }

  condition:
    any of them
}