rule TTP_XOR_MULT_DOSStub_efcf {
  strings:
    $key_efcf = { bb a7 [2] cf bf [2] 88 bd [2] cf ac [2] 81 a0 [2] 8d aa [2] 9a a1 [2] 81 ef [2] bc }

  condition:
    any of them
}