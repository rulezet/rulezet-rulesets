rule TTP_XOR_MULT_DOSStub_efcd {
  strings:
    $key_efcd = { bb a5 [2] cf bd [2] 88 bf [2] cf ae [2] 81 a2 [2] 8d a8 [2] 9a a3 [2] 81 ed [2] bc }

  condition:
    any of them
}