rule TTP_XOR_MULT_DOSStub_21c3 {
  strings:
    $key_21c3 = { 75 ab [2] 01 b3 [2] 46 b1 [2] 01 a0 [2] 4f ac [2] 43 a6 [2] 54 ad [2] 4f e3 [2] 72 }

  condition:
    any of them
}