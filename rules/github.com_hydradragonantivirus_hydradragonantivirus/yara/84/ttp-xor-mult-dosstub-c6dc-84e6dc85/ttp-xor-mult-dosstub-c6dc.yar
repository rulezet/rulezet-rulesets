rule TTP_XOR_MULT_DOSStub_c6dc {
  strings:
    $key_c6dc = { 92 b4 [2] e6 ac [2] a1 ae [2] e6 bf [2] a8 b3 [2] a4 b9 [2] b3 b2 [2] a8 fc [2] 95 }

  condition:
    any of them
}