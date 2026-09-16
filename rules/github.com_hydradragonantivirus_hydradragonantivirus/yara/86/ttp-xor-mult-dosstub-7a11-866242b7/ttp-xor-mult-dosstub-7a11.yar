rule TTP_XOR_MULT_DOSStub_7a11 {
  strings:
    $key_7a11 = { 2e 79 [2] 5a 61 [2] 1d 63 [2] 5a 72 [2] 14 7e [2] 18 74 [2] 0f 7f [2] 14 31 [2] 29 }

  condition:
    any of them
}