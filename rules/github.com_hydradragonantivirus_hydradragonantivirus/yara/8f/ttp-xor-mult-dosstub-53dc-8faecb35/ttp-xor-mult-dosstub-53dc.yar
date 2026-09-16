rule TTP_XOR_MULT_DOSStub_53dc {
  strings:
    $key_53dc = { 07 b4 [2] 73 ac [2] 34 ae [2] 73 bf [2] 3d b3 [2] 31 b9 [2] 26 b2 [2] 3d fc [2] 00 }

  condition:
    any of them
}