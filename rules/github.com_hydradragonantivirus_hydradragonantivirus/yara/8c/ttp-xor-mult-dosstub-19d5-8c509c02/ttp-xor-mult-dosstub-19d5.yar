rule TTP_XOR_MULT_DOSStub_19d5 {
  strings:
    $key_19d5 = { 4d bd [2] 39 a5 [2] 7e a7 [2] 39 b6 [2] 77 ba [2] 7b b0 [2] 6c bb [2] 77 f5 [2] 4a }

  condition:
    any of them
}