rule TTP_XOR_MULT_DOSStub_b663 {
  strings:
    $key_b663 = { e2 0b [2] 96 13 [2] d1 11 [2] 96 00 [2] d8 0c [2] d4 06 [2] c3 0d [2] d8 43 [2] e5 }

  condition:
    any of them
}