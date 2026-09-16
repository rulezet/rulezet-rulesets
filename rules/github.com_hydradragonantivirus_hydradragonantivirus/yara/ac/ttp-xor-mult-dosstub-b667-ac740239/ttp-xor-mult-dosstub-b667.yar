rule TTP_XOR_MULT_DOSStub_b667 {
  strings:
    $key_b667 = { e2 0f [2] 96 17 [2] d1 15 [2] 96 04 [2] d8 08 [2] d4 02 [2] c3 09 [2] d8 47 [2] e5 }

  condition:
    any of them
}