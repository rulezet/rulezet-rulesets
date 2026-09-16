rule TTP_XOR_MULT_DOSStub_6100 {
  strings:
    $key_6100 = { 35 68 [2] 41 70 [2] 06 72 [2] 41 63 [2] 0f 6f [2] 03 65 [2] 14 6e [2] 0f 20 [2] 32 }

  condition:
    any of them
}