rule TTP_XOR_MULT_DOSStub_2091 {
  strings:
    $key_2091 = { 74 f9 [2] 00 e1 [2] 47 e3 [2] 00 f2 [2] 4e fe [2] 42 f4 [2] 55 ff [2] 4e b1 [2] 73 }

  condition:
    any of them
}