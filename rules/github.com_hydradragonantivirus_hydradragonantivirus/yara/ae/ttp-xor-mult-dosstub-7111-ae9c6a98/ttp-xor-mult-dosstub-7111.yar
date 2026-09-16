rule TTP_XOR_MULT_DOSStub_7111 {
  strings:
    $key_7111 = { 25 79 [2] 51 61 [2] 16 63 [2] 51 72 [2] 1f 7e [2] 13 74 [2] 04 7f [2] 1f 31 [2] 22 }

  condition:
    any of them
}