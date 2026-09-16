rule TTP_XOR_MULT_DOSStub_d2cf {
  strings:
    $key_d2cf = { 86 a7 [2] f2 bf [2] b5 bd [2] f2 ac [2] bc a0 [2] b0 aa [2] a7 a1 [2] bc ef [2] 81 }

  condition:
    any of them
}