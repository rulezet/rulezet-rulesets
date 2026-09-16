rule TTP_XOR_MULT_DOSStub_1826 {
  strings:
    $key_1826 = { 4c 4e [2] 38 56 [2] 7f 54 [2] 38 45 [2] 76 49 [2] 7a 43 [2] 6d 48 [2] 76 06 [2] 4b }

  condition:
    any of them
}