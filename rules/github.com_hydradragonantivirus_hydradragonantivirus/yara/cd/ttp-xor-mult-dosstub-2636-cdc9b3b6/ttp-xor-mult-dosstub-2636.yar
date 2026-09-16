rule TTP_XOR_MULT_DOSStub_2636 {
  strings:
    $key_2636 = { 72 5e [2] 06 46 [2] 41 44 [2] 06 55 [2] 48 59 [2] 44 53 [2] 53 58 [2] 48 16 [2] 75 }

  condition:
    any of them
}