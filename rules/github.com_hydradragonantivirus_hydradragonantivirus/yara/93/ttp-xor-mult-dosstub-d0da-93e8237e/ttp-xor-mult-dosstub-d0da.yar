rule TTP_XOR_MULT_DOSStub_d0da {
  strings:
    $key_d0da = { 84 b2 [2] f0 aa [2] b7 a8 [2] f0 b9 [2] be b5 [2] b2 bf [2] a5 b4 [2] be fa [2] 83 }

  condition:
    any of them
}