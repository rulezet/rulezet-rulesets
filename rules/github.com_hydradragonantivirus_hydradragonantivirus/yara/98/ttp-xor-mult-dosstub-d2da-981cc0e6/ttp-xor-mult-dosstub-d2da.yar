rule TTP_XOR_MULT_DOSStub_d2da {
  strings:
    $key_d2da = { 86 b2 [2] f2 aa [2] b5 a8 [2] f2 b9 [2] bc b5 [2] b0 bf [2] a7 b4 [2] bc fa [2] 81 }

  condition:
    any of them
}