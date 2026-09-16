rule TTP_XOR_MULT_DOSStub_1091 {
  strings:
    $key_1091 = { 44 f9 [2] 30 e1 [2] 77 e3 [2] 30 f2 [2] 7e fe [2] 72 f4 [2] 65 ff [2] 7e b1 [2] 43 }

  condition:
    any of them
}