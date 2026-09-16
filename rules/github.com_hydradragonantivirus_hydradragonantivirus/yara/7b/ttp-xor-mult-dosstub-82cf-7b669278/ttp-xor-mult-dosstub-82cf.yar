rule TTP_XOR_MULT_DOSStub_82cf {
  strings:
    $key_82cf = { d6 a7 [2] a2 bf [2] e5 bd [2] a2 ac [2] ec a0 [2] e0 aa [2] f7 a1 [2] ec ef [2] d1 }

  condition:
    any of them
}