rule TTP_XOR_MULT_DOSStub_2631 {
  strings:
    $key_2631 = { 72 59 [2] 06 41 [2] 41 43 [2] 06 52 [2] 48 5e [2] 44 54 [2] 53 5f [2] 48 11 [2] 75 }

  condition:
    any of them
}