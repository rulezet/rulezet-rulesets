rule TTP_XOR_MULT_DOSStub_51dc {
  strings:
    $key_51dc = { 05 b4 [2] 71 ac [2] 36 ae [2] 71 bf [2] 3f b3 [2] 33 b9 [2] 24 b2 [2] 3f fc [2] 02 }

  condition:
    any of them
}