rule TTP_XOR_MULT_DOSStub_0531 {
  strings:
    $key_0531 = { 51 59 [2] 25 41 [2] 62 43 [2] 25 52 [2] 6b 5e [2] 67 54 [2] 70 5f [2] 6b 11 [2] 56 }

  condition:
    any of them
}