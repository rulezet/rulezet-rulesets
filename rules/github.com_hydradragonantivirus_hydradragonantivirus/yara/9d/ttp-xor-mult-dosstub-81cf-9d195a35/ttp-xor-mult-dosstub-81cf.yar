rule TTP_XOR_MULT_DOSStub_81cf {
  strings:
    $key_81cf = { d5 a7 [2] a1 bf [2] e6 bd [2] a1 ac [2] ef a0 [2] e3 aa [2] f4 a1 [2] ef ef [2] d2 }

  condition:
    any of them
}