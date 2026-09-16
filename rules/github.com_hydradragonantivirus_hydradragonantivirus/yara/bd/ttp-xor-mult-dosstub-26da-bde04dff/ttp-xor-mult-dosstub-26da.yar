rule TTP_XOR_MULT_DOSStub_26da {
  strings:
    $key_26da = { 72 b2 [2] 06 aa [2] 41 a8 [2] 06 b9 [2] 48 b5 [2] 44 bf [2] 53 b4 [2] 48 fa [2] 75 }

  condition:
    any of them
}