rule TTP_XOR_MULT_DOSStub_7147 {
  strings:
    $key_7147 = { 25 2f [2] 51 37 [2] 16 35 [2] 51 24 [2] 1f 28 [2] 13 22 [2] 04 29 [2] 1f 67 [2] 22 }

  condition:
    any of them
}