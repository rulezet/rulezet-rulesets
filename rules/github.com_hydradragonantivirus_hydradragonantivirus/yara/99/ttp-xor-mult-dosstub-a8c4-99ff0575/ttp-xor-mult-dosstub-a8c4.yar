rule TTP_XOR_MULT_DOSStub_a8c4 {
  strings:
    $key_a8c4 = { fc ac [2] 88 b4 [2] cf b6 [2] 88 a7 [2] c6 ab [2] ca a1 [2] dd aa [2] c6 e4 [2] fb }

  condition:
    any of them
}