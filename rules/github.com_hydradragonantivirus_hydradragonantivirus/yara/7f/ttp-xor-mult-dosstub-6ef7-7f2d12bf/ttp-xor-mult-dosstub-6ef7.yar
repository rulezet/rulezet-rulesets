rule TTP_XOR_MULT_DOSStub_6ef7 {
  strings:
    $key_6ef7 = { 3a 9f [2] 4e 87 [2] 09 85 [2] 4e 94 [2] 00 98 [2] 0c 92 [2] 1b 99 [2] 00 d7 [2] 3d }

  condition:
    any of them
}