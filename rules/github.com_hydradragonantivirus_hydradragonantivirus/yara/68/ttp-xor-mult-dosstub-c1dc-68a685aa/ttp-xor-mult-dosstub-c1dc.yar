rule TTP_XOR_MULT_DOSStub_c1dc {
  strings:
    $key_c1dc = { 95 b4 [2] e1 ac [2] a6 ae [2] e1 bf [2] af b3 [2] a3 b9 [2] b4 b2 [2] af fc [2] 92 }

  condition:
    any of them
}