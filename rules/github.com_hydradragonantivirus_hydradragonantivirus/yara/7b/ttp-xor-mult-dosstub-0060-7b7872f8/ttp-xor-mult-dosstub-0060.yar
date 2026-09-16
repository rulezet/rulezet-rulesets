rule TTP_XOR_MULT_DOSStub_0060 {
  strings:
    $key_0060 = { 54 08 [2] 20 10 [2] 67 12 [2] 20 03 [2] 6e 0f [2] 62 05 [2] 75 0e [2] 6e 40 [2] 53 }

  condition:
    any of them
}