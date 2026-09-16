rule TTP_XOR_MULT_DOSStub_3a67 {
  strings:
    $key_3a67 = { 6e 0f [2] 1a 17 [2] 5d 15 [2] 1a 04 [2] 54 08 [2] 58 02 [2] 4f 09 [2] 54 47 [2] 69 }

  condition:
    any of them
}