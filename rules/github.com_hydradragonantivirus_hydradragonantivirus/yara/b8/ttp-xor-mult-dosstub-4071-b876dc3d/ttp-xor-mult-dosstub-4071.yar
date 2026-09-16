rule TTP_XOR_MULT_DOSStub_4071 {
  strings:
    $key_4071 = { 14 19 [2] 60 01 [2] 27 03 [2] 60 12 [2] 2e 1e [2] 22 14 [2] 35 1f [2] 2e 51 [2] 13 }

  condition:
    any of them
}