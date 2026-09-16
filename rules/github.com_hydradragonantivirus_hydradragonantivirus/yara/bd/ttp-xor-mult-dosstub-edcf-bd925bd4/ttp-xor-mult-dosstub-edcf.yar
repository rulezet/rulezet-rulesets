rule TTP_XOR_MULT_DOSStub_edcf {
  strings:
    $key_edcf = { b9 a7 [2] cd bf [2] 8a bd [2] cd ac [2] 83 a0 [2] 8f aa [2] 98 a1 [2] 83 ef [2] be }

  condition:
    any of them
}