rule TTP_XOR_MULT_DOSStub_2bd5 {
  strings:
    $key_2bd5 = { 7f bd [2] 0b a5 [2] 4c a7 [2] 0b b6 [2] 45 ba [2] 49 b0 [2] 5e bb [2] 45 f5 [2] 78 }

  condition:
    any of them
}