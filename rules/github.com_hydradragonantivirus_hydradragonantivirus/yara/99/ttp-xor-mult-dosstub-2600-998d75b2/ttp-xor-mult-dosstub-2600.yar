rule TTP_XOR_MULT_DOSStub_2600 {
  strings:
    $key_2600 = { 72 68 [2] 06 70 [2] 41 72 [2] 06 63 [2] 48 6f [2] 44 65 [2] 53 6e [2] 48 20 [2] 75 }

  condition:
    any of them
}