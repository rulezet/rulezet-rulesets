rule TTP_XOR_MULT_DOSStub_a58c {
  strings:
    $key_a58c = { f1 e4 [2] 85 fc [2] c2 fe [2] 85 ef [2] cb e3 [2] c7 e9 [2] d0 e2 [2] cb ac [2] f6 }

  condition:
    any of them
}