rule TTP_XOR_MULT_DOSStub_1391 {
  strings:
    $key_1391 = { 47 f9 [2] 33 e1 [2] 74 e3 [2] 33 f2 [2] 7d fe [2] 71 f4 [2] 66 ff [2] 7d b1 [2] 40 }

  condition:
    any of them
}