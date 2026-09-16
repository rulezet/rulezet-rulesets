rule TTP_XOR_MULT_DOSStub_fada {
  strings:
    $key_fada = { ae b2 [2] da aa [2] 9d a8 [2] da b9 [2] 94 b5 [2] 98 bf [2] 8f b4 [2] 94 fa [2] a9 }

  condition:
    any of them
}