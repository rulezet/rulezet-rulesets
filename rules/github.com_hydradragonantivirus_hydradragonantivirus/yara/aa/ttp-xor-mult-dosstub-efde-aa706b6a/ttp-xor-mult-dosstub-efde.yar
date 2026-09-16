rule TTP_XOR_MULT_DOSStub_efde {
  strings:
    $key_efde = { bb b6 [2] cf ae [2] 88 ac [2] cf bd [2] 81 b1 [2] 8d bb [2] 9a b0 [2] 81 fe [2] bc }

  condition:
    any of them
}