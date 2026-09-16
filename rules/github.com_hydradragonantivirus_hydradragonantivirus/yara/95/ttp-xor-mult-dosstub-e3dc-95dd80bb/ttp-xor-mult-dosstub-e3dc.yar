rule TTP_XOR_MULT_DOSStub_e3dc {
  strings:
    $key_e3dc = { b7 b4 [2] c3 ac [2] 84 ae [2] c3 bf [2] 8d b3 [2] 81 b9 [2] 96 b2 [2] 8d fc [2] b0 }

  condition:
    any of them
}