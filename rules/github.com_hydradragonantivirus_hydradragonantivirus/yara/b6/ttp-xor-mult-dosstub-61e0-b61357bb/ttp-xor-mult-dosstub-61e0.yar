rule TTP_XOR_MULT_DOSStub_61e0 {
  strings:
    $key_61e0 = { 35 88 [2] 41 90 [2] 06 92 [2] 41 83 [2] 0f 8f [2] 03 85 [2] 14 8e [2] 0f c0 [2] 32 }

  condition:
    any of them
}