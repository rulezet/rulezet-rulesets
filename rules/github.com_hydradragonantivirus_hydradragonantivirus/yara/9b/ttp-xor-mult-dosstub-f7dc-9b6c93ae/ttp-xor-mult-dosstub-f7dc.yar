rule TTP_XOR_MULT_DOSStub_f7dc {
  strings:
    $key_f7dc = { a3 b4 [2] d7 ac [2] 90 ae [2] d7 bf [2] 99 b3 [2] 95 b9 [2] 82 b2 [2] 99 fc [2] a4 }

  condition:
    any of them
}