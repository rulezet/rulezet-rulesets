rule TTP_XOR_MULT_DOSStub_3291 {
  strings:
    $key_3291 = { 66 f9 [2] 12 e1 [2] 55 e3 [2] 12 f2 [2] 5c fe [2] 50 f4 [2] 47 ff [2] 5c b1 [2] 61 }

  condition:
    any of them
}