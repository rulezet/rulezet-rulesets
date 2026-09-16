rule TTP_XOR_MULT_DOSStub_3411 {
  strings:
    $key_3411 = { 60 79 [2] 14 61 [2] 53 63 [2] 14 72 [2] 5a 7e [2] 56 74 [2] 41 7f [2] 5a 31 [2] 67 }

  condition:
    any of them
}