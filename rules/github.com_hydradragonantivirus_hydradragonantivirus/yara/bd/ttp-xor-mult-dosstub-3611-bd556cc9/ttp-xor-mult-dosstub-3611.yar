rule TTP_XOR_MULT_DOSStub_3611 {
  strings:
    $key_3611 = { 62 79 [2] 16 61 [2] 51 63 [2] 16 72 [2] 58 7e [2] 54 74 [2] 43 7f [2] 58 31 [2] 65 }

  condition:
    any of them
}