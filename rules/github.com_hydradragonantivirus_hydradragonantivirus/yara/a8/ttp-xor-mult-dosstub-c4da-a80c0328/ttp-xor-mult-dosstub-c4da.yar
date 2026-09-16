rule TTP_XOR_MULT_DOSStub_c4da {
  strings:
    $key_c4da = { 90 b2 [2] e4 aa [2] a3 a8 [2] e4 b9 [2] aa b5 [2] a6 bf [2] b1 b4 [2] aa fa [2] 97 }

  condition:
    any of them
}