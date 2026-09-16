rule TTP_XOR_MULT_DOSStub_6536 {
  strings:
    $key_6536 = { 31 5e [2] 45 46 [2] 02 44 [2] 45 55 [2] 0b 59 [2] 07 53 [2] 10 58 [2] 0b 16 [2] 36 }

  condition:
    any of them
}