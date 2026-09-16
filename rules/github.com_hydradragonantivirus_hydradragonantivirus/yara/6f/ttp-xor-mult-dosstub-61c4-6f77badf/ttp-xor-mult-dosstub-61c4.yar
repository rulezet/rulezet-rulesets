rule TTP_XOR_MULT_DOSStub_61c4 {
  strings:
    $key_61c4 = { 35 ac [2] 41 b4 [2] 06 b6 [2] 41 a7 [2] 0f ab [2] 03 a1 [2] 14 aa [2] 0f e4 [2] 32 }

  condition:
    any of them
}