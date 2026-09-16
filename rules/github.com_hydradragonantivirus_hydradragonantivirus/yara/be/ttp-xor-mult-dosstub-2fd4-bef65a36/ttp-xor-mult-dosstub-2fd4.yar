rule TTP_XOR_MULT_DOSStub_2fd4 {
  strings:
    $key_2fd4 = { 7b bc [2] 0f a4 [2] 48 a6 [2] 0f b7 [2] 41 bb [2] 4d b1 [2] 5a ba [2] 41 f4 [2] 7c }

  condition:
    any of them
}