rule TTP_XOR_MULT_DOSStub_0560 {
  strings:
    $key_0560 = { 51 08 [2] 25 10 [2] 62 12 [2] 25 03 [2] 6b 0f [2] 67 05 [2] 70 0e [2] 6b 40 [2] 56 }

  condition:
    any of them
}