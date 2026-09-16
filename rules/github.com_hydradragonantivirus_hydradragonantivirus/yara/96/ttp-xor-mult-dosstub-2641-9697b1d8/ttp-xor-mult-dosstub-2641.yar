rule TTP_XOR_MULT_DOSStub_2641 {
  strings:
    $key_2641 = { 72 29 [2] 06 31 [2] 41 33 [2] 06 22 [2] 48 2e [2] 44 24 [2] 53 2f [2] 48 61 [2] 75 }

  condition:
    any of them
}