rule TTP_XOR_MULT_DOSStub_1ac5 {
  strings:
    $key_1ac5 = { 4e ad [2] 3a b5 [2] 7d b7 [2] 3a a6 [2] 74 aa [2] 78 a0 [2] 6f ab [2] 74 e5 [2] 49 }

  condition:
    any of them
}