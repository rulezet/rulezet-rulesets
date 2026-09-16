rule TTP_XOR_MULT_DOSStub_3fc3 {
  strings:
    $key_3fc3 = { 6b ab [2] 1f b3 [2] 58 b1 [2] 1f a0 [2] 51 ac [2] 5d a6 [2] 4a ad [2] 51 e3 [2] 6c }

  condition:
    any of them
}