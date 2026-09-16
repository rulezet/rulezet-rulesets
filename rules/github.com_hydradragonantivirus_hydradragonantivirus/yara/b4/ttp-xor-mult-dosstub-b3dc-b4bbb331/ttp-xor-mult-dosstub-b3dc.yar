rule TTP_XOR_MULT_DOSStub_b3dc {
  strings:
    $key_b3dc = { e7 b4 [2] 93 ac [2] d4 ae [2] 93 bf [2] dd b3 [2] d1 b9 [2] c6 b2 [2] dd fc [2] e0 }

  condition:
    any of them
}