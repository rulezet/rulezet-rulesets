rule TTP_XOR_MULT_DOSStub_b254 {
  strings:
    $key_b254 = { e6 3c [2] 92 24 [2] d5 26 [2] 92 37 [2] dc 3b [2] d0 31 [2] c7 3a [2] dc 74 [2] e1 }

  condition:
    any of them
}