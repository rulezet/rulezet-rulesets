rule TTP_XOR_MULT_DOSStub_efc9 {
  strings:
    $key_efc9 = { bb a1 [2] cf b9 [2] 88 bb [2] cf aa [2] 81 a6 [2] 8d ac [2] 9a a7 [2] 81 e9 [2] bc }

  condition:
    any of them
}