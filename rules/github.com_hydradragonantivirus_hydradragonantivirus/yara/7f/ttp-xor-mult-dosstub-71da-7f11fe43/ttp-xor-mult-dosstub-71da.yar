rule TTP_XOR_MULT_DOSStub_71da {
  strings:
    $key_71da = { 25 b2 [2] 51 aa [2] 16 a8 [2] 51 b9 [2] 1f b5 [2] 13 bf [2] 04 b4 [2] 1f fa [2] 22 }

  condition:
    any of them
}