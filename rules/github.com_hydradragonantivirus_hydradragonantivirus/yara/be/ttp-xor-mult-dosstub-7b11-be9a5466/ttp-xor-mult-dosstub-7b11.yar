rule TTP_XOR_MULT_DOSStub_7b11 {
  strings:
    $key_7b11 = { 2f 79 [2] 5b 61 [2] 1c 63 [2] 5b 72 [2] 15 7e [2] 19 74 [2] 0e 7f [2] 15 31 [2] 28 }

  condition:
    any of them
}