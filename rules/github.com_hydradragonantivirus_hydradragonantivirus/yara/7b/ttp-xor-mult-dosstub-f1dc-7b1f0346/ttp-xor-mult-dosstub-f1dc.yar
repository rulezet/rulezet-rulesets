rule TTP_XOR_MULT_DOSStub_f1dc {
  strings:
    $key_f1dc = { a5 b4 [2] d1 ac [2] 96 ae [2] d1 bf [2] 9f b3 [2] 93 b9 [2] 84 b2 [2] 9f fc [2] a2 }

  condition:
    any of them
}