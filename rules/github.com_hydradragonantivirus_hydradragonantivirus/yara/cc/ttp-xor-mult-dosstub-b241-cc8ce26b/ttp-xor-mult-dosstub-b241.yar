rule TTP_XOR_MULT_DOSStub_b241 {
  strings:
    $key_b241 = { e6 29 [2] 92 31 [2] d5 33 [2] 92 22 [2] dc 2e [2] d0 24 [2] c7 2f [2] dc 61 [2] e1 }

  condition:
    any of them
}