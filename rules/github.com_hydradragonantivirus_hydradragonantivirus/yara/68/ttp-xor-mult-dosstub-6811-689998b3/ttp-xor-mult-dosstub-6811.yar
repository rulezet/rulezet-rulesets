rule TTP_XOR_MULT_DOSStub_6811 {
  strings:
    $key_6811 = { 3c 79 [2] 48 61 [2] 0f 63 [2] 48 72 [2] 06 7e [2] 0a 74 [2] 1d 7f [2] 06 31 [2] 3b }

  condition:
    any of them
}