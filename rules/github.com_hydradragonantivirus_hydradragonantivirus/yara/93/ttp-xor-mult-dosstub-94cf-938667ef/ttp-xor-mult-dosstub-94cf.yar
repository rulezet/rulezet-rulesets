rule TTP_XOR_MULT_DOSStub_94cf {
  strings:
    $key_94cf = { c0 a7 [2] b4 bf [2] f3 bd [2] b4 ac [2] fa a0 [2] f6 aa [2] e1 a1 [2] fa ef [2] c7 }

  condition:
    any of them
}