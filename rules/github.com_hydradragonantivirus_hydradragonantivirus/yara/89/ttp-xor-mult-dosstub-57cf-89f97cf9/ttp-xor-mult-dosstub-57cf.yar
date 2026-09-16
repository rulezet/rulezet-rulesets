rule TTP_XOR_MULT_DOSStub_57cf {
  strings:
    $key_57cf = { 03 a7 [2] 77 bf [2] 30 bd [2] 77 ac [2] 39 a0 [2] 35 aa [2] 22 a1 [2] 39 ef [2] 04 }

  condition:
    any of them
}