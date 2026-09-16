rule TTP_XOR_MULT_DOSStub_b664 {
  strings:
    $key_b664 = { e2 0c [2] 96 14 [2] d1 16 [2] 96 07 [2] d8 0b [2] d4 01 [2] c3 0a [2] d8 44 [2] e5 }

  condition:
    any of them
}