rule TTP_XOR_MULT_DOSStub_1801 {
  strings:
    $key_1801 = { 4c 69 [2] 38 71 [2] 7f 73 [2] 38 62 [2] 76 6e [2] 7a 64 [2] 6d 6f [2] 76 21 [2] 4b }

  condition:
    any of them
}