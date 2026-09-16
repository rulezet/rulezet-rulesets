rule TTP_XOR_MULT_DOSStub_6ec5 {
  strings:
    $key_6ec5 = { 3a ad [2] 4e b5 [2] 09 b7 [2] 4e a6 [2] 00 aa [2] 0c a0 [2] 1b ab [2] 00 e5 [2] 3d }

  condition:
    any of them
}