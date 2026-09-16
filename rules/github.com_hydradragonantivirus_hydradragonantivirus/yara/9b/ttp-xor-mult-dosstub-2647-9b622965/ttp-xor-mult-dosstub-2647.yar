rule TTP_XOR_MULT_DOSStub_2647 {
  strings:
    $key_2647 = { 72 2f [2] 06 37 [2] 41 35 [2] 06 24 [2] 48 28 [2] 44 22 [2] 53 29 [2] 48 67 [2] 75 }

  condition:
    any of them
}