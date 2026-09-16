rule TTP_XOR_MULT_DOSStub_b669 {
  strings:
    $key_b669 = { e2 01 [2] 96 19 [2] d1 1b [2] 96 0a [2] d8 06 [2] d4 0c [2] c3 07 [2] d8 49 [2] e5 }

  condition:
    any of them
}