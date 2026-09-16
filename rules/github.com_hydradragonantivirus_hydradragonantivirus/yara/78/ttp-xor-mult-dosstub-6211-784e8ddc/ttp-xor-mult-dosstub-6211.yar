rule TTP_XOR_MULT_DOSStub_6211 {
  strings:
    $key_6211 = { 36 79 [2] 42 61 [2] 05 63 [2] 42 72 [2] 0c 7e [2] 00 74 [2] 17 7f [2] 0c 31 [2] 31 }

  condition:
    any of them
}