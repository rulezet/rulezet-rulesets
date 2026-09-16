rule TTP_XOR_MULT_DOSStub_f7da {
  strings:
    $key_f7da = { a3 b2 [2] d7 aa [2] 90 a8 [2] d7 b9 [2] 99 b5 [2] 95 bf [2] 82 b4 [2] 99 fa [2] a4 }

  condition:
    any of them
}