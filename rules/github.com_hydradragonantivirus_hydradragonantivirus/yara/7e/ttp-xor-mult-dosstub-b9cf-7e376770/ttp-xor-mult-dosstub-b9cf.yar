rule TTP_XOR_MULT_DOSStub_b9cf {
  strings:
    $key_b9cf = { ed a7 [2] 99 bf [2] de bd [2] 99 ac [2] d7 a0 [2] db aa [2] cc a1 [2] d7 ef [2] ea }

  condition:
    any of them
}