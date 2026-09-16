rule TTP_XOR_MULT_DOSStub_53cf {
  strings:
    $key_53cf = { 07 a7 [2] 73 bf [2] 34 bd [2] 73 ac [2] 3d a0 [2] 31 aa [2] 26 a1 [2] 3d ef [2] 00 }

  condition:
    any of them
}