rule TTP_XOR_MULT_DOSStub_dbcf {
  strings:
    $key_dbcf = { 8f a7 [2] fb bf [2] bc bd [2] fb ac [2] b5 a0 [2] b9 aa [2] ae a1 [2] b5 ef [2] 88 }

  condition:
    any of them
}