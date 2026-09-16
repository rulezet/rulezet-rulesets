rule TTP_XOR_MULT_DOSStub_b256 {
  strings:
    $key_b256 = { e6 3e [2] 92 26 [2] d5 24 [2] 92 35 [2] dc 39 [2] d0 33 [2] c7 38 [2] dc 76 [2] e1 }

  condition:
    any of them
}