rule TTP_XOR_MULT_DOSStub_e9dc {
  strings:
    $key_e9dc = { bd b4 [2] c9 ac [2] 8e ae [2] c9 bf [2] 87 b3 [2] 8b b9 [2] 9c b2 [2] 87 fc [2] ba }

  condition:
    any of them
}