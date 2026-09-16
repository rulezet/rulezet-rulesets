rule TTP_XOR_MULT_DOSStub_1fd5 {
  strings:
    $key_1fd5 = { 4b bd [2] 3f a5 [2] 78 a7 [2] 3f b6 [2] 71 ba [2] 7d b0 [2] 6a bb [2] 71 f5 [2] 4c }

  condition:
    any of them
}