rule TTP_XOR_MULT_DOSStub_13dc {
  strings:
    $key_13dc = { 47 b4 [2] 33 ac [2] 74 ae [2] 33 bf [2] 7d b3 [2] 71 b9 [2] 66 b2 [2] 7d fc [2] 40 }

  condition:
    any of them
}