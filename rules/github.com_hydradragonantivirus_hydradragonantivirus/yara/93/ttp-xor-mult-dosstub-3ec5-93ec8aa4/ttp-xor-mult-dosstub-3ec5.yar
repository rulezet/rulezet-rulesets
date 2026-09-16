rule TTP_XOR_MULT_DOSStub_3ec5 {
  strings:
    $key_3ec5 = { 6a ad [2] 1e b5 [2] 59 b7 [2] 1e a6 [2] 50 aa [2] 5c a0 [2] 4b ab [2] 50 e5 [2] 6d }

  condition:
    any of them
}