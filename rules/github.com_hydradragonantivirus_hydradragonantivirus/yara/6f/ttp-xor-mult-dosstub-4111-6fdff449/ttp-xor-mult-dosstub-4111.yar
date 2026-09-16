rule TTP_XOR_MULT_DOSStub_4111 {
  strings:
    $key_4111 = { 15 79 [2] 61 61 [2] 26 63 [2] 61 72 [2] 2f 7e [2] 23 74 [2] 34 7f [2] 2f 31 [2] 12 }

  condition:
    any of them
}