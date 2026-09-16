rule TTP_XOR_MULT_DOSStub_6541 {
  strings:
    $key_6541 = { 31 29 [2] 45 31 [2] 02 33 [2] 45 22 [2] 0b 2e [2] 07 24 [2] 10 2f [2] 0b 61 [2] 36 }

  condition:
    any of them
}