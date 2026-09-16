rule TTP_XOR_MULT_DOSStub_b205 {
  strings:
    $key_b205 = { e6 6d [2] 92 75 [2] d5 77 [2] 92 66 [2] dc 6a [2] d0 60 [2] c7 6b [2] dc 25 [2] e1 }

  condition:
    any of them
}