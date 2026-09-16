rule TTP_XOR_MULT_DOSStub_e1dc {
  strings:
    $key_e1dc = { b5 b4 [2] c1 ac [2] 86 ae [2] c1 bf [2] 8f b3 [2] 83 b9 [2] 94 b2 [2] 8f fc [2] b2 }

  condition:
    any of them
}