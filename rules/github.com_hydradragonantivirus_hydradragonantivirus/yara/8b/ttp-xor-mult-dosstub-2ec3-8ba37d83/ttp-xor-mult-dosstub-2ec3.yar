rule TTP_XOR_MULT_DOSStub_2ec3 {
  strings:
    $key_2ec3 = { 7a ab [2] 0e b3 [2] 49 b1 [2] 0e a0 [2] 40 ac [2] 4c a6 [2] 5b ad [2] 40 e3 [2] 7d }

  condition:
    any of them
}