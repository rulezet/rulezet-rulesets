rule TTP_XOR_MULT_DOSStub_2211 {
  strings:
    $key_2211 = { 76 79 [2] 02 61 [2] 45 63 [2] 02 72 [2] 4c 7e [2] 40 74 [2] 57 7f [2] 4c 31 [2] 71 }

  condition:
    any of them
}