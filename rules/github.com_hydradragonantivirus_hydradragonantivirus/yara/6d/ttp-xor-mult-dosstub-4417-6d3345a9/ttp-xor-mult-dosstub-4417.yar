rule TTP_XOR_MULT_DOSStub_4417 {
  strings:
    $key_4417 = { 10 7f [2] 64 67 [2] 23 65 [2] 64 74 [2] 2a 78 [2] 26 72 [2] 31 79 [2] 2a 37 [2] 17 }

  condition:
    any of them
}