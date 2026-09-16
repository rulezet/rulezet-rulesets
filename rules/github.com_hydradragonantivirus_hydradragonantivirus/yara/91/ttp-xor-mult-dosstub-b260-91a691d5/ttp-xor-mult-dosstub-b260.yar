rule TTP_XOR_MULT_DOSStub_b260 {
  strings:
    $key_b260 = { e6 08 [2] 92 10 [2] d5 12 [2] 92 03 [2] dc 0f [2] d0 05 [2] c7 0e [2] dc 40 [2] e1 }

  condition:
    any of them
}