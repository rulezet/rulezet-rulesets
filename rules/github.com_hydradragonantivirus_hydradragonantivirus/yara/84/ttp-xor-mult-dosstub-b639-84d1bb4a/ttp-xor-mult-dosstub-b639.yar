rule TTP_XOR_MULT_DOSStub_b639 {
  strings:
    $key_b639 = { e2 51 [2] 96 49 [2] d1 4b [2] 96 5a [2] d8 56 [2] d4 5c [2] c3 57 [2] d8 19 [2] e5 }

  condition:
    any of them
}