rule TTP_XOR_MULT_DOSStub_1ec3 {
  strings:
    $key_1ec3 = { 4a ab [2] 3e b3 [2] 79 b1 [2] 3e a0 [2] 70 ac [2] 7c a6 [2] 6b ad [2] 70 e3 [2] 4d }

  condition:
    any of them
}