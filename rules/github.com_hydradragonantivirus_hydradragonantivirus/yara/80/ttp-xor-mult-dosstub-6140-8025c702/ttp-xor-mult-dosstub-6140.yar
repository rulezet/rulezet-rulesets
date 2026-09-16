rule TTP_XOR_MULT_DOSStub_6140 {
  strings:
    $key_6140 = { 35 28 [2] 41 30 [2] 06 32 [2] 41 23 [2] 0f 2f [2] 03 25 [2] 14 2e [2] 0f 60 [2] 32 }

  condition:
    any of them
}