rule TTP_XOR_MULT_DOSStub_89cf {
  strings:
    $key_89cf = { dd a7 [2] a9 bf [2] ee bd [2] a9 ac [2] e7 a0 [2] eb aa [2] fc a1 [2] e7 ef [2] da }

  condition:
    any of them
}