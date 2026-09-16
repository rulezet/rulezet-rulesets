rule TTP_XOR_MULT_DOSStub_6117 {
  strings:
    $key_6117 = { 35 7f [2] 41 67 [2] 06 65 [2] 41 74 [2] 0f 78 [2] 03 72 [2] 14 79 [2] 0f 37 [2] 32 }

  condition:
    any of them
}