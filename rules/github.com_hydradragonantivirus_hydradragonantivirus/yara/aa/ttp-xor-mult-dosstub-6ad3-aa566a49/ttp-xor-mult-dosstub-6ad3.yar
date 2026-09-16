rule TTP_XOR_MULT_DOSStub_6ad3 {
  strings:
    $key_6ad3 = { 3e bb [2] 4a a3 [2] 0d a1 [2] 4a b0 [2] 04 bc [2] 08 b6 [2] 1f bd [2] 04 f3 [2] 39 }

  condition:
    any of them
}