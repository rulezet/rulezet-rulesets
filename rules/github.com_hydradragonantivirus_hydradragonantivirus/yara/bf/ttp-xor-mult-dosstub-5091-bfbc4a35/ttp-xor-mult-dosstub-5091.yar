rule TTP_XOR_MULT_DOSStub_5091 {
  strings:
    $key_5091 = { 04 f9 [2] 70 e1 [2] 37 e3 [2] 70 f2 [2] 3e fe [2] 32 f4 [2] 25 ff [2] 3e b1 [2] 03 }

  condition:
    any of them
}