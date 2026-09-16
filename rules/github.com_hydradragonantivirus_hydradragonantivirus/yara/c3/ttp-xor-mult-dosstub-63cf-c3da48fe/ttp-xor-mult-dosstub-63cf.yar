rule TTP_XOR_MULT_DOSStub_63cf {
  strings:
    $key_63cf = { 37 a7 [2] 43 bf [2] 04 bd [2] 43 ac [2] 0d a0 [2] 01 aa [2] 16 a1 [2] 0d ef [2] 30 }

  condition:
    any of them
}