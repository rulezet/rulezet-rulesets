rule TTP_XOR_MULT_DOSStub_34da {
  strings:
    $key_34da = { 60 b2 [2] 14 aa [2] 53 a8 [2] 14 b9 [2] 5a b5 [2] 56 bf [2] 41 b4 [2] 5a fa [2] 67 }

  condition:
    any of them
}