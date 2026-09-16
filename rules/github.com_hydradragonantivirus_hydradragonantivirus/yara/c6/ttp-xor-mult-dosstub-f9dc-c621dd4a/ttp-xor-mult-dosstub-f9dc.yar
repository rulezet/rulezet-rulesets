rule TTP_XOR_MULT_DOSStub_f9dc {
  strings:
    $key_f9dc = { ad b4 [2] d9 ac [2] 9e ae [2] d9 bf [2] 97 b3 [2] 9b b9 [2] 8c b2 [2] 97 fc [2] aa }

  condition:
    any of them
}