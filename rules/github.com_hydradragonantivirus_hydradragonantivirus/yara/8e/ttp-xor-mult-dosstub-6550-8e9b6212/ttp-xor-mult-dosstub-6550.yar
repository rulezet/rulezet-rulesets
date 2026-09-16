rule TTP_XOR_MULT_DOSStub_6550 {
  strings:
    $key_6550 = { 31 38 [2] 45 20 [2] 02 22 [2] 45 33 [2] 0b 3f [2] 07 35 [2] 10 3e [2] 0b 70 [2] 36 }

  condition:
    any of them
}