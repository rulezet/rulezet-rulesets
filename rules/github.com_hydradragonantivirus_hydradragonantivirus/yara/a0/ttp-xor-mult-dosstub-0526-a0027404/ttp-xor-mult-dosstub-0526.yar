rule TTP_XOR_MULT_DOSStub_0526 {
  strings:
    $key_0526 = { 51 4e [2] 25 56 [2] 62 54 [2] 25 45 [2] 6b 49 [2] 67 43 [2] 70 48 [2] 6b 06 [2] 56 }

  condition:
    any of them
}