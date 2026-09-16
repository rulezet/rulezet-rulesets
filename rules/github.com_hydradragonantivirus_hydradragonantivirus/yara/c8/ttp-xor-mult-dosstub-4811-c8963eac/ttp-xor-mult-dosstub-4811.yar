rule TTP_XOR_MULT_DOSStub_4811 {
  strings:
    $key_4811 = { 1c 79 [2] 68 61 [2] 2f 63 [2] 68 72 [2] 26 7e [2] 2a 74 [2] 3d 7f [2] 26 31 [2] 1b }

  condition:
    any of them
}