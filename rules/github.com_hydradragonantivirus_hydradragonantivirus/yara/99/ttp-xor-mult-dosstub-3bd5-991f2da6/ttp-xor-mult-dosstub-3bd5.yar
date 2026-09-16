rule TTP_XOR_MULT_DOSStub_3bd5 {
  strings:
    $key_3bd5 = { 6f bd [2] 1b a5 [2] 5c a7 [2] 1b b6 [2] 55 ba [2] 59 b0 [2] 4e bb [2] 55 f5 [2] 68 }

  condition:
    any of them
}