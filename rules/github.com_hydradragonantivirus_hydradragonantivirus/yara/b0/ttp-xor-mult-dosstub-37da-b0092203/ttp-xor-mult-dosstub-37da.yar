rule TTP_XOR_MULT_DOSStub_37da {
  strings:
    $key_37da = { 63 b2 [2] 17 aa [2] 50 a8 [2] 17 b9 [2] 59 b5 [2] 55 bf [2] 42 b4 [2] 59 fa [2] 64 }

  condition:
    any of them
}