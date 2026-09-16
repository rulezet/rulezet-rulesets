rule TTP_XOR_MULT_DOSStub_d5dc {
  strings:
    $key_d5dc = { 81 b4 [2] f5 ac [2] b2 ae [2] f5 bf [2] bb b3 [2] b7 b9 [2] a0 b2 [2] bb fc [2] 86 }

  condition:
    any of them
}