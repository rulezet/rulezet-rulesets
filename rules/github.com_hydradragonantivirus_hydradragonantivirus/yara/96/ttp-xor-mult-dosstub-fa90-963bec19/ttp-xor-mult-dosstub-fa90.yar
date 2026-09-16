rule TTP_XOR_MULT_DOSStub_fa90 {
  strings:
    $key_fa90 = { ae f8 [2] da e0 [2] 9d e2 [2] da f3 [2] 94 ff [2] 98 f5 [2] 8f fe [2] 94 b0 [2] a9 }

  condition:
    any of them
}