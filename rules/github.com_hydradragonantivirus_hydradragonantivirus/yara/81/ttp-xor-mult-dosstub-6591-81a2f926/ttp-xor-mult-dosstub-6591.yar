rule TTP_XOR_MULT_DOSStub_6591 {
  strings:
    $key_6591 = { 31 f9 [2] 45 e1 [2] 02 e3 [2] 45 f2 [2] 0b fe [2] 07 f4 [2] 10 ff [2] 0b b1 [2] 36 }

  condition:
    any of them
}