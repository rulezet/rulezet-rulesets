rule TTP_XOR_MULT_DOSStub_d5da {
  strings:
    $key_d5da = { 81 b2 [2] f5 aa [2] b2 a8 [2] f5 b9 [2] bb b5 [2] b7 bf [2] a0 b4 [2] bb fa [2] 86 }

  condition:
    any of them
}