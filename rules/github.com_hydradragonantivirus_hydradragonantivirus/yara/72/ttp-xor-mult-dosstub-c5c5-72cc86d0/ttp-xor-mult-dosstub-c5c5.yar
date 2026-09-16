rule TTP_XOR_MULT_DOSStub_c5c5 {
  strings:
    $key_c5c5 = { 91 ad [2] e5 b5 [2] a2 b7 [2] e5 a6 [2] ab aa [2] a7 a0 [2] b0 ab [2] ab e5 [2] 96 }

  condition:
    any of them
}