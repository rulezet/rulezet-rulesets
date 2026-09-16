rule TTP_XOR_MULT_DOSStub_7ec5 {
  strings:
    $key_7ec5 = { 2a ad [2] 5e b5 [2] 19 b7 [2] 5e a6 [2] 10 aa [2] 1c a0 [2] 0b ab [2] 10 e5 [2] 2d }

  condition:
    any of them
}