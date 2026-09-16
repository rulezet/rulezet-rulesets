rule TTP_XOR_MULT_DOSStub_1fd1 {
  strings:
    $key_1fd1 = { 4b b9 [2] 3f a1 [2] 78 a3 [2] 3f b2 [2] 71 be [2] 7d b4 [2] 6a bf [2] 71 f1 [2] 4c }

  condition:
    any of them
}