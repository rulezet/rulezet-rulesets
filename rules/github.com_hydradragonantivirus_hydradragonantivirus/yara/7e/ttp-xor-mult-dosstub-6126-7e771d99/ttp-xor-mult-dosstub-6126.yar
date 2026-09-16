rule TTP_XOR_MULT_DOSStub_6126 {
  strings:
    $key_6126 = { 35 4e [2] 41 56 [2] 06 54 [2] 41 45 [2] 0f 49 [2] 03 43 [2] 14 48 [2] 0f 06 [2] 32 }

  condition:
    any of them
}