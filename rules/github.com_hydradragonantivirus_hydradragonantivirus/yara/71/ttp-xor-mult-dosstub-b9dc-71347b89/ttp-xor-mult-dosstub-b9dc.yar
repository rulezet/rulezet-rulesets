rule TTP_XOR_MULT_DOSStub_b9dc {
  strings:
    $key_b9dc = { ed b4 [2] 99 ac [2] de ae [2] 99 bf [2] d7 b3 [2] db b9 [2] cc b2 [2] d7 fc [2] ea }

  condition:
    any of them
}