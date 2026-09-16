rule TTP_XOR_MULT_DOSStub_b7dc {
  strings:
    $key_b7dc = { e3 b4 [2] 97 ac [2] d0 ae [2] 97 bf [2] d9 b3 [2] d5 b9 [2] c2 b2 [2] d9 fc [2] e4 }

  condition:
    any of them
}