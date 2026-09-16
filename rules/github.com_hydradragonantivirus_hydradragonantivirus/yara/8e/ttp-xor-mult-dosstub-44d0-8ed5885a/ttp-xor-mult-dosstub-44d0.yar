rule TTP_XOR_MULT_DOSStub_44d0 {
  strings:
    $key_44d0 = { 10 b8 [2] 64 a0 [2] 23 a2 [2] 64 b3 [2] 2a bf [2] 26 b5 [2] 31 be [2] 2a f0 [2] 17 }

  condition:
    any of them
}