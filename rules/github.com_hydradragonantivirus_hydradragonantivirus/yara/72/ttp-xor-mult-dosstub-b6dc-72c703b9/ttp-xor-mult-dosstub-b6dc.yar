rule TTP_XOR_MULT_DOSStub_b6dc {
  strings:
    $key_b6dc = { e2 b4 [2] 96 ac [2] d1 ae [2] 96 bf [2] d8 b3 [2] d4 b9 [2] c3 b2 [2] d8 fc [2] e5 }

  condition:
    any of them
}