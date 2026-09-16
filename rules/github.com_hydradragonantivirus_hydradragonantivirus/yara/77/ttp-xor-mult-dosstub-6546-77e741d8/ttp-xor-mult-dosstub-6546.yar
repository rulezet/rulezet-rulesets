rule TTP_XOR_MULT_DOSStub_6546 {
  strings:
    $key_6546 = { 31 2e [2] 45 36 [2] 02 34 [2] 45 25 [2] 0b 29 [2] 07 23 [2] 10 28 [2] 0b 66 [2] 36 }

  condition:
    any of them
}