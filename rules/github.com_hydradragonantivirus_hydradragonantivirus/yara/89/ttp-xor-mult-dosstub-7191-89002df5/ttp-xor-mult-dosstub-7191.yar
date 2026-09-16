rule TTP_XOR_MULT_DOSStub_7191 {
  strings:
    $key_7191 = { 25 f9 [2] 51 e1 [2] 16 e3 [2] 51 f2 [2] 1f fe [2] 13 f4 [2] 04 ff [2] 1f b1 [2] 22 }

  condition:
    any of them
}