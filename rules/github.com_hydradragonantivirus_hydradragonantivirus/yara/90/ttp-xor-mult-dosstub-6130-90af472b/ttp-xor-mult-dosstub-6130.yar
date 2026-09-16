rule TTP_XOR_MULT_DOSStub_6130 {
  strings:
    $key_6130 = { 35 58 [2] 41 40 [2] 06 42 [2] 41 53 [2] 0f 5f [2] 03 55 [2] 14 5e [2] 0f 10 [2] 32 }

  condition:
    any of them
}