rule TTP_XOR_MULT_DOSStub_7b26 {
  strings:
    $key_7b26 = { 2f 4e [2] 5b 56 [2] 1c 54 [2] 5b 45 [2] 15 49 [2] 19 43 [2] 0e 48 [2] 15 06 [2] 28 }

  condition:
    any of them
}