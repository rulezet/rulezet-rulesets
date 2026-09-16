rule TTP_XOR_MULT_DOSStub_5acc {
  strings:
    $key_5acc = { 0e a4 [2] 7a bc [2] 3d be [2] 7a af [2] 34 a3 [2] 38 a9 [2] 2f a2 [2] 34 ec [2] 09 }

  condition:
    any of them
}