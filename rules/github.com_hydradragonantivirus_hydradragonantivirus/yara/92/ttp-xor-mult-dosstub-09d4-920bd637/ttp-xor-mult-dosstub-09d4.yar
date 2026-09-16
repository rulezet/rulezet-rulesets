rule TTP_XOR_MULT_DOSStub_09d4 {
  strings:
    $key_09d4 = { 5d bc [2] 29 a4 [2] 6e a6 [2] 29 b7 [2] 67 bb [2] 6b b1 [2] 7c ba [2] 67 f4 [2] 5a }

  condition:
    any of them
}