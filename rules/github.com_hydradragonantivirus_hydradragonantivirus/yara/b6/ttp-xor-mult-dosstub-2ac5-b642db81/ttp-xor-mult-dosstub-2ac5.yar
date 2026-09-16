rule TTP_XOR_MULT_DOSStub_2ac5 {
  strings:
    $key_2ac5 = { 7e ad [2] 0a b5 [2] 4d b7 [2] 0a a6 [2] 44 aa [2] 48 a0 [2] 5f ab [2] 44 e5 [2] 79 }

  condition:
    any of them
}