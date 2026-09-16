rule TTP_XOR_MULT_DOSStub_b609 {
  strings:
    $key_b609 = { e2 61 [2] 96 79 [2] d1 7b [2] 96 6a [2] d8 66 [2] d4 6c [2] c3 67 [2] d8 29 [2] e5 }

  condition:
    any of them
}