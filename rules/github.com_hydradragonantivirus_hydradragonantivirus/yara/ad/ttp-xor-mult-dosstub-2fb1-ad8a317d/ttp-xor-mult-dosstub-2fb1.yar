rule TTP_XOR_MULT_DOSStub_2fb1 {
  strings:
    $key_2fb1 = { 7b d9 [2] 0f c1 [2] 48 c3 [2] 0f d2 [2] 41 de [2] 4d d4 [2] 5a df [2] 41 91 [2] 7c }

  condition:
    any of them
}