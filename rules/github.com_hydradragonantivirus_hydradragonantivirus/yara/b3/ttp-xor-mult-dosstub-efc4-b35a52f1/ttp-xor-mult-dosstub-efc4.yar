rule TTP_XOR_MULT_DOSStub_efc4 {
  strings:
    $key_efc4 = { bb ac [2] cf b4 [2] 88 b6 [2] cf a7 [2] 81 ab [2] 8d a1 [2] 9a aa [2] 81 e4 [2] bc }

  condition:
    any of them
}