rule TTP_XOR_MULT_DOSStub_4bd5 {
  strings:
    $key_4bd5 = { 1f bd [2] 6b a5 [2] 2c a7 [2] 6b b6 [2] 25 ba [2] 29 b0 [2] 3e bb [2] 25 f5 [2] 18 }

  condition:
    any of them
}