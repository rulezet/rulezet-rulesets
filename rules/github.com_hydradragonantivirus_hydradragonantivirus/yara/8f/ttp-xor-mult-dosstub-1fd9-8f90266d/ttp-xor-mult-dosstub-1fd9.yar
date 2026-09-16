rule TTP_XOR_MULT_DOSStub_1fd9 {
  strings:
    $key_1fd9 = { 4b b1 [2] 3f a9 [2] 78 ab [2] 3f ba [2] 71 b6 [2] 7d bc [2] 6a b7 [2] 71 f9 [2] 4c }

  condition:
    any of them
}