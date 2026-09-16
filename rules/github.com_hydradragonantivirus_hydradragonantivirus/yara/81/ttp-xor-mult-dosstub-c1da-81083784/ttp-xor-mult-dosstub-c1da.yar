rule TTP_XOR_MULT_DOSStub_c1da {
  strings:
    $key_c1da = { 95 b2 [2] e1 aa [2] a6 a8 [2] e1 b9 [2] af b5 [2] a3 bf [2] b4 b4 [2] af fa [2] 92 }

  condition:
    any of them
}