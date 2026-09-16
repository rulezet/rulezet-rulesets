rule TTP_XOR_MULT_DOSStub_90da {
  strings:
    $key_90da = { c4 b2 [2] b0 aa [2] f7 a8 [2] b0 b9 [2] fe b5 [2] f2 bf [2] e5 b4 [2] fe fa [2] c3 }

  condition:
    any of them
}