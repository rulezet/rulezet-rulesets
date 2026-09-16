rule TTP_XOR_MULT_DOSStub_6510 {
  strings:
    $key_6510 = { 31 78 [2] 45 60 [2] 02 62 [2] 45 73 [2] 0b 7f [2] 07 75 [2] 10 7e [2] 0b 30 [2] 36 }

  condition:
    any of them
}