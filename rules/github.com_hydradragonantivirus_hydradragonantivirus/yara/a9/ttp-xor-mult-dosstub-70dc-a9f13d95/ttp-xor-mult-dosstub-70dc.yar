rule TTP_XOR_MULT_DOSStub_70dc {
  strings:
    $key_70dc = { 24 b4 [2] 50 ac [2] 17 ae [2] 50 bf [2] 1e b3 [2] 12 b9 [2] 05 b2 [2] 1e fc [2] 23 }

  condition:
    any of them
}