rule TTP_XOR_MULT_DOSStub_c4dc {
  strings:
    $key_c4dc = { 90 b4 [2] e4 ac [2] a3 ae [2] e4 bf [2] aa b3 [2] a6 b9 [2] b1 b2 [2] aa fc [2] 97 }

  condition:
    any of them
}