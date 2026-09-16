rule TTP_XOR_MULT_DOSStub_2811 {
  strings:
    $key_2811 = { 7c 79 [2] 08 61 [2] 4f 63 [2] 08 72 [2] 46 7e [2] 4a 74 [2] 5d 7f [2] 46 31 [2] 7b }

  condition:
    any of them
}