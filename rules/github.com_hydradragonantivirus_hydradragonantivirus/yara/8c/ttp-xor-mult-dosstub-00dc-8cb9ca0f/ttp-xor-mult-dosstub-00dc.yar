rule TTP_XOR_MULT_DOSStub_00dc {
  strings:
    $key_00dc = { 54 b4 [2] 20 ac [2] 67 ae [2] 20 bf [2] 6e b3 [2] 62 b9 [2] 75 b2 [2] 6e fc [2] 53 }

  condition:
    any of them
}