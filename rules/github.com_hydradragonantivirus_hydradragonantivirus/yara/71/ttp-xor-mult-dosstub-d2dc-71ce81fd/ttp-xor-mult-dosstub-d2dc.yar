rule TTP_XOR_MULT_DOSStub_d2dc {
  strings:
    $key_d2dc = { 86 b4 [2] f2 ac [2] b5 ae [2] f2 bf [2] bc b3 [2] b0 b9 [2] a7 b2 [2] bc fc [2] 81 }

  condition:
    any of them
}