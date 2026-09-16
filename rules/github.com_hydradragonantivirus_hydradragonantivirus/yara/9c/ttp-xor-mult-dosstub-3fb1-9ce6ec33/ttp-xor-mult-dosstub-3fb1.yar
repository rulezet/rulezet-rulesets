rule TTP_XOR_MULT_DOSStub_3fb1 {
  strings:
    $key_3fb1 = { 6b d9 [2] 1f c1 [2] 58 c3 [2] 1f d2 [2] 51 de [2] 5d d4 [2] 4a df [2] 51 91 [2] 6c }

  condition:
    any of them
}