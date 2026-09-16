rule TTP_XOR_MULT_DOSStub_6111 {
  strings:
    $key_6111 = { 35 79 [2] 41 61 [2] 06 63 [2] 41 72 [2] 0f 7e [2] 03 74 [2] 14 7f [2] 0f 31 [2] 32 }

  condition:
    any of them
}