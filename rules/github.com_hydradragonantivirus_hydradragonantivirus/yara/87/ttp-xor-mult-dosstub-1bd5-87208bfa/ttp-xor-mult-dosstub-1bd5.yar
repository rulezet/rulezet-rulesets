rule TTP_XOR_MULT_DOSStub_1bd5 {
  strings:
    $key_1bd5 = { 4f bd [2] 3b a5 [2] 7c a7 [2] 3b b6 [2] 75 ba [2] 79 b0 [2] 6e bb [2] 75 f5 [2] 48 }

  condition:
    any of them
}