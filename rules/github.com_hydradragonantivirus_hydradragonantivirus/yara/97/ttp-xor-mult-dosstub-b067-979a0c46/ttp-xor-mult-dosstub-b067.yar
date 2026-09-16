rule TTP_XOR_MULT_DOSStub_b067 {
  strings:
    $key_b067 = { e4 0f [2] 90 17 [2] d7 15 [2] 90 04 [2] de 08 [2] d2 02 [2] c5 09 [2] de 47 [2] e3 }

  condition:
    any of them
}