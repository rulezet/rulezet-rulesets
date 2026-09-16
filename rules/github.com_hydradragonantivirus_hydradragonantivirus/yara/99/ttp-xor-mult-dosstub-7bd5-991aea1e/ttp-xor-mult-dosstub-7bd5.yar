rule TTP_XOR_MULT_DOSStub_7bd5 {
  strings:
    $key_7bd5 = { 2f bd [2] 5b a5 [2] 1c a7 [2] 5b b6 [2] 15 ba [2] 19 b0 [2] 0e bb [2] 15 f5 [2] 28 }

  condition:
    any of them
}