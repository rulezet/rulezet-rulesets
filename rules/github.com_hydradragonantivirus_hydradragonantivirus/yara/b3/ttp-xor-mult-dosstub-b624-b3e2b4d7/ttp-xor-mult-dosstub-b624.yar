rule TTP_XOR_MULT_DOSStub_b624 {
  strings:
    $key_b624 = { e2 4c [2] 96 54 [2] d1 56 [2] 96 47 [2] d8 4b [2] d4 41 [2] c3 4a [2] d8 04 [2] e5 }

  condition:
    any of them
}