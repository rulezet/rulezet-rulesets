rule TTP_XOR_MULT_DOSStub_61c2 {
  strings:
    $key_61c2 = { 35 aa [2] 41 b2 [2] 06 b0 [2] 41 a1 [2] 0f ad [2] 03 a7 [2] 14 ac [2] 0f e2 [2] 32 }

  condition:
    any of them
}