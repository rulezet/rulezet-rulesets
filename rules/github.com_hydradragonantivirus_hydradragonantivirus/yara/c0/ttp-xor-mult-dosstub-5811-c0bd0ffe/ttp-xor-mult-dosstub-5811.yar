rule TTP_XOR_MULT_DOSStub_5811 {
  strings:
    $key_5811 = { 0c 79 [2] 78 61 [2] 3f 63 [2] 78 72 [2] 36 7e [2] 3a 74 [2] 2d 7f [2] 36 31 [2] 0b }

  condition:
    any of them
}