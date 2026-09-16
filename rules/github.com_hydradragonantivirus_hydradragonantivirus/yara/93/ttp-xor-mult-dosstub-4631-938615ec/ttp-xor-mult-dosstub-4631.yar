rule TTP_XOR_MULT_DOSStub_4631 {
  strings:
    $key_4631 = { 12 59 [2] 66 41 [2] 21 43 [2] 66 52 [2] 28 5e [2] 24 54 [2] 33 5f [2] 28 11 [2] 15 }

  condition:
    any of them
}