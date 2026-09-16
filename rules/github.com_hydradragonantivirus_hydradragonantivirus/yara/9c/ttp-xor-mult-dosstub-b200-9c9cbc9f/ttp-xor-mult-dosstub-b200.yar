rule TTP_XOR_MULT_DOSStub_b200 {
  strings:
    $key_b200 = { e6 68 [2] 92 70 [2] d5 72 [2] 92 63 [2] dc 6f [2] d0 65 [2] c7 6e [2] dc 20 [2] e1 }

  condition:
    any of them
}