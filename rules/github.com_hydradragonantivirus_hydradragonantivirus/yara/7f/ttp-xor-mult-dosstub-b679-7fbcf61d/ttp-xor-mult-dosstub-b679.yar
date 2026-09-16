rule TTP_XOR_MULT_DOSStub_b679 {
  strings:
    $key_b679 = { e2 11 [2] 96 09 [2] d1 0b [2] 96 1a [2] d8 16 [2] d4 1c [2] c3 17 [2] d8 59 [2] e5 }

  condition:
    any of them
}