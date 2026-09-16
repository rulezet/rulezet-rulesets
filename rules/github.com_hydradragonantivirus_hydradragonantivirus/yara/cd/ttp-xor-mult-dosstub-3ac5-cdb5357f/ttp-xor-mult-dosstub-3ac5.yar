rule TTP_XOR_MULT_DOSStub_3ac5 {
  strings:
    $key_3ac5 = { 6e ad [2] 1a b5 [2] 5d b7 [2] 1a a6 [2] 54 aa [2] 58 a0 [2] 4f ab [2] 54 e5 [2] 69 }

  condition:
    any of them
}