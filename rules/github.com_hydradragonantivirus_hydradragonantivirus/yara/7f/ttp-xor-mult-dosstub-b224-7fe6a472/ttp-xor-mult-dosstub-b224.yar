rule TTP_XOR_MULT_DOSStub_b224 {
  strings:
    $key_b224 = { e6 4c [2] 92 54 [2] d5 56 [2] 92 47 [2] dc 4b [2] d0 41 [2] c7 4a [2] dc 04 [2] e1 }

  condition:
    any of them
}