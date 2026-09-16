rule TTP_XOR_MULT_DOSStub_7ad3 {
  strings:
    $key_7ad3 = { 2e bb [2] 5a a3 [2] 1d a1 [2] 5a b0 [2] 14 bc [2] 18 b6 [2] 0f bd [2] 14 f3 [2] 29 }

  condition:
    any of them
}