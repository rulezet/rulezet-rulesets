rule TTP_XOR_MULT_DOSStub_06da {
  strings:
    $key_06da = { 52 b2 [2] 26 aa [2] 61 a8 [2] 26 b9 [2] 68 b5 [2] 64 bf [2] 73 b4 [2] 68 fa [2] 55 }

  condition:
    any of them
}