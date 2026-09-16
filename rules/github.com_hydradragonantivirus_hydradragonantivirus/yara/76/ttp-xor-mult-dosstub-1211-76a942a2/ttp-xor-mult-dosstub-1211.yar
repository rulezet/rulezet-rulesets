rule TTP_XOR_MULT_DOSStub_1211 {
  strings:
    $key_1211 = { 46 79 [2] 32 61 [2] 75 63 [2] 32 72 [2] 7c 7e [2] 70 74 [2] 67 7f [2] 7c 31 [2] 41 }

  condition:
    any of them
}