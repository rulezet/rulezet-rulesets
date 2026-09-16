rule TTP_XOR_MULT_DOSStub_7391 {
  strings:
    $key_7391 = { 27 f9 [2] 53 e1 [2] 14 e3 [2] 53 f2 [2] 1d fe [2] 11 f4 [2] 06 ff [2] 1d b1 [2] 20 }

  condition:
    any of them
}