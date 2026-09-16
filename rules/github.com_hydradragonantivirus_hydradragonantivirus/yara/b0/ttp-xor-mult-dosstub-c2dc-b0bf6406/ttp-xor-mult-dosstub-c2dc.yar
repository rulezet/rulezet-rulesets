rule TTP_XOR_MULT_DOSStub_c2dc {
  strings:
    $key_c2dc = { 96 b4 [2] e2 ac [2] a5 ae [2] e2 bf [2] ac b3 [2] a0 b9 [2] b7 b2 [2] ac fc [2] 91 }

  condition:
    any of them
}