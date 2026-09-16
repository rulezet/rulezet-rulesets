rule TTP_XOR_MULT_DOSStub_0ad3 {
  strings:
    $key_0ad3 = { 5e bb [2] 2a a3 [2] 6d a1 [2] 2a b0 [2] 64 bc [2] 68 b6 [2] 7f bd [2] 64 f3 [2] 59 }

  condition:
    any of them
}