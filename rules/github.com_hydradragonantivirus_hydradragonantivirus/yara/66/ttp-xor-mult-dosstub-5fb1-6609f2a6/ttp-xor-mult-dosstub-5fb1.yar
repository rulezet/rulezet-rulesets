rule TTP_XOR_MULT_DOSStub_5fb1 {
  strings:
    $key_5fb1 = { 0b d9 [2] 7f c1 [2] 38 c3 [2] 7f d2 [2] 31 de [2] 3d d4 [2] 2a df [2] 31 91 [2] 0c }

  condition:
    any of them
}