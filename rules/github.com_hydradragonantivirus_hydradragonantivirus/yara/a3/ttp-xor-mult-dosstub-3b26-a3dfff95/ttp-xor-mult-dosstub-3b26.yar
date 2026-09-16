rule TTP_XOR_MULT_DOSStub_3b26 {
  strings:
    $key_3b26 = { 6f 4e [2] 1b 56 [2] 5c 54 [2] 1b 45 [2] 55 49 [2] 59 43 [2] 4e 48 [2] 55 06 [2] 68 }

  condition:
    any of them
}