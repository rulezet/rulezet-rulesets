rule TTP_XOR_MULT_DOSStub_26c5 {
  strings:
    $key_26c5 = { 72 ad [2] 06 b5 [2] 41 b7 [2] 06 a6 [2] 48 aa [2] 44 a0 [2] 53 ab [2] 48 e5 [2] 75 }

  condition:
    any of them
}