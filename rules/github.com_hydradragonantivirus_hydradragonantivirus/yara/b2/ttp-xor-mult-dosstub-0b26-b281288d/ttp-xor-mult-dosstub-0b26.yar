rule TTP_XOR_MULT_DOSStub_0b26 {
  strings:
    $key_0b26 = { 5f 4e [2] 2b 56 [2] 6c 54 [2] 2b 45 [2] 65 49 [2] 69 43 [2] 7e 48 [2] 65 06 [2] 58 }

  condition:
    any of them
}