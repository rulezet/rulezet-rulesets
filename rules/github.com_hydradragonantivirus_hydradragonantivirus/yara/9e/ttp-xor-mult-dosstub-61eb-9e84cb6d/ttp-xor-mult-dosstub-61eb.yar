rule TTP_XOR_MULT_DOSStub_61eb {
  strings:
    $key_61eb = { 35 83 [2] 41 9b [2] 06 99 [2] 41 88 [2] 0f 84 [2] 03 8e [2] 14 85 [2] 0f cb [2] 32 }

  condition:
    any of them
}