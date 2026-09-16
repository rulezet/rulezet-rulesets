rule TTP_XOR_MULT_DOSStub_2a06 {
  strings:
    $key_2a06 = { 7e 6e [2] 0a 76 [2] 4d 74 [2] 0a 65 [2] 44 69 [2] 48 63 [2] 5f 68 [2] 44 26 [2] 79 }

  condition:
    any of them
}