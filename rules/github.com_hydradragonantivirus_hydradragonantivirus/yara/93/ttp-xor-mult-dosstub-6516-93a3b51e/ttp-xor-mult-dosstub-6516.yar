rule TTP_XOR_MULT_DOSStub_6516 {
  strings:
    $key_6516 = { 31 7e [2] 45 66 [2] 02 64 [2] 45 75 [2] 0b 79 [2] 07 73 [2] 10 78 [2] 0b 36 [2] 36 }

  condition:
    any of them
}