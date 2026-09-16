rule TTP_XOR_MULT_DOSStub_f2dc {
  strings:
    $key_f2dc = { a6 b4 [2] d2 ac [2] 95 ae [2] d2 bf [2] 9c b3 [2] 90 b9 [2] 87 b2 [2] 9c fc [2] a1 }

  condition:
    any of them
}