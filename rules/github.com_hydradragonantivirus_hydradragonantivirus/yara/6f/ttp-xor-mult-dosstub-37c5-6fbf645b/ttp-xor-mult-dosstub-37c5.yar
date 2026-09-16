rule TTP_XOR_MULT_DOSStub_37c5 {
  strings:
    $key_37c5 = { 63 ad [2] 17 b5 [2] 50 b7 [2] 17 a6 [2] 59 aa [2] 55 a0 [2] 42 ab [2] 59 e5 [2] 64 }

  condition:
    any of them
}