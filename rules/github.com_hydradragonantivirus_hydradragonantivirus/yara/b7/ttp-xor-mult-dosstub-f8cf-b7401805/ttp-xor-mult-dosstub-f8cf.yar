rule TTP_XOR_MULT_DOSStub_f8cf {
  strings:
    $key_f8cf = { ac a7 [2] d8 bf [2] 9f bd [2] d8 ac [2] 96 a0 [2] 9a aa [2] 8d a1 [2] 96 ef [2] ab }

  condition:
    any of them
}