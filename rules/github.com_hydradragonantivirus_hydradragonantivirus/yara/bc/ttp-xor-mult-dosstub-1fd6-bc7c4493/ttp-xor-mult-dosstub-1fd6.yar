rule TTP_XOR_MULT_DOSStub_1fd6 {
  strings:
    $key_1fd6 = { 4b be [2] 3f a6 [2] 78 a4 [2] 3f b5 [2] 71 b9 [2] 7d b3 [2] 6a b8 [2] 71 f6 [2] 4c }

  condition:
    any of them
}