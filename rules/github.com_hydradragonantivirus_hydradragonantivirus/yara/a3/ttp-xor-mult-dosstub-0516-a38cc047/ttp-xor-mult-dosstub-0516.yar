rule TTP_XOR_MULT_DOSStub_0516 {
  strings:
    $key_0516 = { 51 7e [2] 25 66 [2] 62 64 [2] 25 75 [2] 6b 79 [2] 67 73 [2] 70 78 [2] 6b 36 [2] 56 }

  condition:
    any of them
}