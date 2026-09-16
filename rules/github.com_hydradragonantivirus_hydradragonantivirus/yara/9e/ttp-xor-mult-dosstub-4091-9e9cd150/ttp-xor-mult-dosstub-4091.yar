rule TTP_XOR_MULT_DOSStub_4091 {
  strings:
    $key_4091 = { 14 f9 [2] 60 e1 [2] 27 e3 [2] 60 f2 [2] 2e fe [2] 22 f4 [2] 35 ff [2] 2e b1 [2] 13 }

  condition:
    any of them
}