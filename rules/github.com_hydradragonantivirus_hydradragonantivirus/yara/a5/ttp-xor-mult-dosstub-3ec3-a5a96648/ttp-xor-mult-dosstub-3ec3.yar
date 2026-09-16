rule TTP_XOR_MULT_DOSStub_3ec3 {
  strings:
    $key_3ec3 = { 6a ab [2] 1e b3 [2] 59 b1 [2] 1e a0 [2] 50 ac [2] 5c a6 [2] 4b ad [2] 50 e3 [2] 6d }

  condition:
    any of them
}