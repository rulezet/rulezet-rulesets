rule TTP_XOR_MULT_DOSStub_61f6 {
  strings:
    $key_61f6 = { 35 9e [2] 41 86 [2] 06 84 [2] 41 95 [2] 0f 99 [2] 03 93 [2] 14 98 [2] 0f d6 [2] 32 }

  condition:
    any of them
}