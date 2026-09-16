rule TTP_XOR_MULT_DOSStub_1667 {
  strings:
    $key_1667 = { 42 0f [2] 36 17 [2] 71 15 [2] 36 04 [2] 78 08 [2] 74 02 [2] 63 09 [2] 78 47 [2] 45 }

  condition:
    any of them
}