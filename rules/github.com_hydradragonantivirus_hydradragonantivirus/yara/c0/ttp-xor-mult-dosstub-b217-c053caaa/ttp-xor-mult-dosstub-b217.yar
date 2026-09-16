rule TTP_XOR_MULT_DOSStub_b217 {
  strings:
    $key_b217 = { e6 7f [2] 92 67 [2] d5 65 [2] 92 74 [2] dc 78 [2] d0 72 [2] c7 79 [2] dc 37 [2] e1 }

  condition:
    any of them
}