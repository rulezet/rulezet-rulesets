rule TTP_XOR_MULT_DOSStub_0077 {
  strings:
    $key_0077 = { 54 1f [2] 20 07 [2] 67 05 [2] 20 14 [2] 6e 18 [2] 62 12 [2] 75 19 [2] 6e 57 [2] 53 }

  condition:
    any of them
}