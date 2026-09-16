rule TTP_XOR_MULT_DOSStub_b666 {
  strings:
    $key_b666 = { e2 0e [2] 96 16 [2] d1 14 [2] 96 05 [2] d8 09 [2] d4 03 [2] c3 08 [2] d8 46 [2] e5 }

  condition:
    any of them
}