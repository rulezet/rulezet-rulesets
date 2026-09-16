rule TTP_XOR_MULT_DOSStub_e0dc {
  strings:
    $key_e0dc = { b4 b4 [2] c0 ac [2] 87 ae [2] c0 bf [2] 8e b3 [2] 82 b9 [2] 95 b2 [2] 8e fc [2] b3 }

  condition:
    any of them
}