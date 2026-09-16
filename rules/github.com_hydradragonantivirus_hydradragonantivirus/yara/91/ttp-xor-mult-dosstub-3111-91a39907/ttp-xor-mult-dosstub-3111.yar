rule TTP_XOR_MULT_DOSStub_3111 {
  strings:
    $key_3111 = { 65 79 [2] 11 61 [2] 56 63 [2] 11 72 [2] 5f 7e [2] 53 74 [2] 44 7f [2] 5f 31 [2] 62 }

  condition:
    any of them
}