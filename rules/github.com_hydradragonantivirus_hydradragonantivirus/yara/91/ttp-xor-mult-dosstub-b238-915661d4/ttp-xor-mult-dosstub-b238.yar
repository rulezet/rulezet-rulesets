rule TTP_XOR_MULT_DOSStub_b238 {
  strings:
    $key_b238 = { e6 50 [2] 92 48 [2] d5 4a [2] 92 5b [2] dc 57 [2] d0 5d [2] c7 56 [2] dc 18 [2] e1 }

  condition:
    any of them
}