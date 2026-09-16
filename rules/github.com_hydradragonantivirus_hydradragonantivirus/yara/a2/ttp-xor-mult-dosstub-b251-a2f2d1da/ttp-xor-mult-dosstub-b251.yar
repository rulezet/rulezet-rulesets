rule TTP_XOR_MULT_DOSStub_b251 {
  strings:
    $key_b251 = { e6 39 [2] 92 21 [2] d5 23 [2] 92 32 [2] dc 3e [2] d0 34 [2] c7 3f [2] dc 71 [2] e1 }

  condition:
    any of them
}