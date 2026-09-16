rule TTP_XOR_MULT_DOSStub_c5c3 {
  strings:
    $key_c5c3 = { 91 ab [2] e5 b3 [2] a2 b1 [2] e5 a0 [2] ab ac [2] a7 a6 [2] b0 ad [2] ab e3 [2] 96 }

  condition:
    any of them
}