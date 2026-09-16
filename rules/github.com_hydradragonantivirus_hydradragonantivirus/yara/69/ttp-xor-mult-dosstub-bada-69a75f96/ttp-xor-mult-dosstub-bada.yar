rule TTP_XOR_MULT_DOSStub_bada {
  strings:
    $key_bada = { ee b2 [2] 9a aa [2] dd a8 [2] 9a b9 [2] d4 b5 [2] d8 bf [2] cf b4 [2] d4 fa [2] e9 }

  condition:
    any of them
}