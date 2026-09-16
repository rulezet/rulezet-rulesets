rule TTP_XOR_MULT_DOSStub_1fd4 {
  strings:
    $key_1fd4 = { 4b bc [2] 3f a4 [2] 78 a6 [2] 3f b7 [2] 71 bb [2] 7d b1 [2] 6a ba [2] 71 f4 [2] 4c }

  condition:
    any of them
}