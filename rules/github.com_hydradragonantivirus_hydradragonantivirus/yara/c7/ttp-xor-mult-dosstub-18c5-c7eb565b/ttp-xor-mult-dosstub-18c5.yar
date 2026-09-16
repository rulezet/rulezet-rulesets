rule TTP_XOR_MULT_DOSStub_18c5 {
  strings:
    $key_18c5 = { 4c ad [2] 38 b5 [2] 7f b7 [2] 38 a6 [2] 76 aa [2] 7a a0 [2] 6d ab [2] 76 e5 [2] 4b }

  condition:
    any of them
}