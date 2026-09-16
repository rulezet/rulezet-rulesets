rule TTP_XOR_MULT_DOSStub_96dc {
  strings:
    $key_96dc = { c2 b4 [2] b6 ac [2] f1 ae [2] b6 bf [2] f8 b3 [2] f4 b9 [2] e3 b2 [2] f8 fc [2] c5 }

  condition:
    any of them
}