rule TTP_XOR_MULT_DOSStub_fa95 {
  strings:
    $key_fa95 = { ae fd [2] da e5 [2] 9d e7 [2] da f6 [2] 94 fa [2] 98 f0 [2] 8f fb [2] 94 b5 [2] a9 }

  condition:
    any of them
}