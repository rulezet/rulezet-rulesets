rule TTP_XOR_MULT_DOSStub_2191 {
  strings:
    $key_2191 = { 75 f9 [2] 01 e1 [2] 46 e3 [2] 01 f2 [2] 4f fe [2] 43 f4 [2] 54 ff [2] 4f b1 [2] 72 }

  condition:
    any of them
}