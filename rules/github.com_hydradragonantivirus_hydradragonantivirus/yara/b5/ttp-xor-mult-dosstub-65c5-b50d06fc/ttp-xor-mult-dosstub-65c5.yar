rule TTP_XOR_MULT_DOSStub_65c5 {
  strings:
    $key_65c5 = { 31 ad [2] 45 b5 [2] 02 b7 [2] 45 a6 [2] 0b aa [2] 07 a0 [2] 10 ab [2] 0b e5 [2] 36 }

  condition:
    any of them
}