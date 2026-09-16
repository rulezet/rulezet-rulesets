rule TTP_XOR_MULT_DOSStub_e4dc {
  strings:
    $key_e4dc = { b0 b4 [2] c4 ac [2] 83 ae [2] c4 bf [2] 8a b3 [2] 86 b9 [2] 91 b2 [2] 8a fc [2] b7 }

  condition:
    any of them
}