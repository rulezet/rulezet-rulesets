rule TTP_XOR_MULT_DOSStub_5ec5 {
  strings:
    $key_5ec5 = { 0a ad [2] 7e b5 [2] 39 b7 [2] 7e a6 [2] 30 aa [2] 3c a0 [2] 2b ab [2] 30 e5 [2] 0d }

  condition:
    any of them
}