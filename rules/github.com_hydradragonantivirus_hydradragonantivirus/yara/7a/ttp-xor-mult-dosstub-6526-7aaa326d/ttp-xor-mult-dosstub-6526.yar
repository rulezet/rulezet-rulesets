rule TTP_XOR_MULT_DOSStub_6526 {
  strings:
    $key_6526 = { 31 4e [2] 45 56 [2] 02 54 [2] 45 45 [2] 0b 49 [2] 07 43 [2] 10 48 [2] 0b 06 [2] 36 }

  condition:
    any of them
}