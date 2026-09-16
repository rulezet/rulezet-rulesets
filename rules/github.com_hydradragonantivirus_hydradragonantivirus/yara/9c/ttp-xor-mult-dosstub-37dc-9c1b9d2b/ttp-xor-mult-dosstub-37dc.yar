rule TTP_XOR_MULT_DOSStub_37dc {
  strings:
    $key_37dc = { 63 b4 [2] 17 ac [2] 50 ae [2] 17 bf [2] 59 b3 [2] 55 b9 [2] 42 b2 [2] 59 fc [2] 64 }

  condition:
    any of them
}