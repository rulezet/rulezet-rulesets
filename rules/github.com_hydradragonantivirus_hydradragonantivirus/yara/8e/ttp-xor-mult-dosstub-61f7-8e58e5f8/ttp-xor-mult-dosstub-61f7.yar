rule TTP_XOR_MULT_DOSStub_61f7 {
  strings:
    $key_61f7 = { 35 9f [2] 41 87 [2] 06 85 [2] 41 94 [2] 0f 98 [2] 03 92 [2] 14 99 [2] 0f d7 [2] 32 }

  condition:
    any of them
}