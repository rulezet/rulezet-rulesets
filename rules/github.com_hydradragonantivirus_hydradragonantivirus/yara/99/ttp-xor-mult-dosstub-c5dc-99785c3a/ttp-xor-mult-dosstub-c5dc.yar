rule TTP_XOR_MULT_DOSStub_c5dc {
  strings:
    $key_c5dc = { 91 b4 [2] e5 ac [2] a2 ae [2] e5 bf [2] ab b3 [2] a7 b9 [2] b0 b2 [2] ab fc [2] 96 }

  condition:
    any of them
}