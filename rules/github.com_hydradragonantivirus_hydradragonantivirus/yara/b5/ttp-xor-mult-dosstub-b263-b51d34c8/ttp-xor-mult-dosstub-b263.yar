rule TTP_XOR_MULT_DOSStub_b263 {
  strings:
    $key_b263 = { e6 0b [2] 92 13 [2] d5 11 [2] 92 00 [2] dc 0c [2] d0 06 [2] c7 0d [2] dc 43 [2] e1 }

  condition:
    any of them
}