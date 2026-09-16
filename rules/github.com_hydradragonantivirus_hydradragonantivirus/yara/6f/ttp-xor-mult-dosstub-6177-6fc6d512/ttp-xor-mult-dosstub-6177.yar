rule TTP_XOR_MULT_DOSStub_6177 {
  strings:
    $key_6177 = { 35 1f [2] 41 07 [2] 06 05 [2] 41 14 [2] 0f 18 [2] 03 12 [2] 14 19 [2] 0f 57 [2] 32 }

  condition:
    any of them
}