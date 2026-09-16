rule TTP_XOR_MULT_DOSStub_5fa4 {
  strings:
    $key_5fa4 = { 0b cc [2] 7f d4 [2] 38 d6 [2] 7f c7 [2] 31 cb [2] 3d c1 [2] 2a ca [2] 31 84 [2] 0c }

  condition:
    any of them
}