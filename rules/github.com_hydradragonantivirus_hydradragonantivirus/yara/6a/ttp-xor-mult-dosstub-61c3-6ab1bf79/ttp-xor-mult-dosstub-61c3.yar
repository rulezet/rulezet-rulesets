rule TTP_XOR_MULT_DOSStub_61c3 {
  strings:
    $key_61c3 = { 35 ab [2] 41 b3 [2] 06 b1 [2] 41 a0 [2] 0f ac [2] 03 a6 [2] 14 ad [2] 0f e3 [2] 32 }

  condition:
    any of them
}