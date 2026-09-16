rule TTP_XOR_MULT_DOSStub_6101 {
  strings:
    $key_6101 = { 35 69 [2] 41 71 [2] 06 73 [2] 41 62 [2] 0f 6e [2] 03 64 [2] 14 6f [2] 0f 21 [2] 32 }

  condition:
    any of them
}