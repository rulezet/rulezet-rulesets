rule TTP_XOR_MULT_DOSStub_2515 {
  strings:
    $key_2515 = { 71 7d [2] 05 65 [2] 42 67 [2] 05 76 [2] 4b 7a [2] 47 70 [2] 50 7b [2] 4b 35 [2] 76 }

  condition:
    any of them
}