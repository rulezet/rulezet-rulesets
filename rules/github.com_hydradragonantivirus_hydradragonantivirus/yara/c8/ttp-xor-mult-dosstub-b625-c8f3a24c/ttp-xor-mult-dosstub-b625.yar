rule TTP_XOR_MULT_DOSStub_b625 {
  strings:
    $key_b625 = { e2 4d [2] 96 55 [2] d1 57 [2] 96 46 [2] d8 4a [2] d4 40 [2] c3 4b [2] d8 05 [2] e5 }

  condition:
    any of them
}