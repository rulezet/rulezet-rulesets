rule TTP_XOR_MULT_DOSStub_08c5 {
  strings:
    $key_08c5 = { 5c ad [2] 28 b5 [2] 6f b7 [2] 28 a6 [2] 66 aa [2] 6a a0 [2] 7d ab [2] 66 e5 [2] 5b }

  condition:
    any of them
}