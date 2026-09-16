rule TTP_XOR_MULT_DOSStub_11c8 {
  strings:
    $key_11c8 = { 45 a0 [2] 31 b8 [2] 76 ba [2] 31 ab [2] 7f a7 [2] 73 ad [2] 64 a6 [2] 7f e8 [2] 42 }

  condition:
    any of them
}