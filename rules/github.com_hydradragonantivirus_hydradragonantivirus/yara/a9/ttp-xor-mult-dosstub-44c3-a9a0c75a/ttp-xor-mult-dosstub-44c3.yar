rule TTP_XOR_MULT_DOSStub_44c3 {
  strings:
    $key_44c3 = { 10 ab [2] 64 b3 [2] 23 b1 [2] 64 a0 [2] 2a ac [2] 26 a6 [2] 31 ad [2] 2a e3 [2] 17 }

  condition:
    any of them
}