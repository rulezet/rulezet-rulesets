rule TTP_XOR_MULT_DOSStub_3ad3 {
  strings:
    $key_3ad3 = { 6e bb [2] 1a a3 [2] 5d a1 [2] 1a b0 [2] 54 bc [2] 58 b6 [2] 4f bd [2] 54 f3 [2] 69 }

  condition:
    any of them
}