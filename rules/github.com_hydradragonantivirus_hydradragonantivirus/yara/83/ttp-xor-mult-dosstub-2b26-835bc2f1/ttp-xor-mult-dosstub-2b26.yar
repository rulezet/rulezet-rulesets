rule TTP_XOR_MULT_DOSStub_2b26 {
  strings:
    $key_2b26 = { 7f 4e [2] 0b 56 [2] 4c 54 [2] 0b 45 [2] 45 49 [2] 49 43 [2] 5e 48 [2] 45 06 [2] 78 }

  condition:
    any of them
}