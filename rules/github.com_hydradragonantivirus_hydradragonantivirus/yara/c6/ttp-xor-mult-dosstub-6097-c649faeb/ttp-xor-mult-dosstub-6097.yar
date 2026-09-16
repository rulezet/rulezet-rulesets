rule TTP_XOR_MULT_DOSStub_6097 {
  strings:
    $key_6097 = { 34 ff [2] 40 e7 [2] 07 e5 [2] 40 f4 [2] 0e f8 [2] 02 f2 [2] 15 f9 [2] 0e b7 [2] 33 }

  condition:
    any of them
}