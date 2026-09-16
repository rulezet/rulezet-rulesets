rule TTP_XOR_MULT_DOSStub_1631 {
  strings:
    $key_1631 = { 42 59 [2] 36 41 [2] 71 43 [2] 36 52 [2] 78 5e [2] 74 54 [2] 63 5f [2] 78 11 [2] 45 }

  condition:
    any of them
}